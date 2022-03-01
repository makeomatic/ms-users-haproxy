const fs = require('fs').promises;
const { deepStrictEqual } = require('assert');
const { delay } = require('bluebird');

const axios = require('axios').default;
const ld = require('lodash');

const jwt = require('jsonwebtoken');
const app = require('../../src/fastify-app');

const ConsulUtil = require('../util/consul');
const { clearRedis } = require('../util/redis');

const haServer = 'http://haproxy:8080';
const consulServer = 'consul';
const keyPrefix = 'microfleet/ms-users/revocation-rules';
const consulUtil = new ConsulUtil(consulServer, keyPrefix);

axios.defaults.baseURL = haServer;

const haGet = async (token) => {
  const response = await axios.get('/', {
    headers: {
      authorization: token ? `JWT ${token}` : undefined,
      // 'Authorization': token ? `Bearer ${token}` : undefined
    },
  });
  const interesting = Object.keys(response.data).filter((p) => p.startsWith('x-'));

  return ld.pick(response.data, interesting);
};

describe('HaProxy lua', () => {
  let privateKeys;

  const signRsa = (payload) => jwt.sign({ ...payload }, privateKeys.rsa, { algorithm: 'RS256' });
  // const signEs = (payload) => jwt.sign({ ...payload }, privateKeys.es, { algorithm: 'ES256' })
  const signHmac = (payload) => jwt.sign({ ...payload }, privateKeys.hs, { algorithm: 'HS256' });

  const validateResponse = (res, expected) => {
    const prefix = 'x-tkn';
    Object.entries(expected).forEach(([k, v]) => {
      const prop = `${prefix}-${k}`;
      deepStrictEqual(res[prop], v, `header '${prop}' should have value '${v}' but has '${res[prop]}'`);
    });
  };

  before(async () => {
    privateKeys = {
      rsa: {
        key: await fs.readFile(`${__dirname}/../keys/rsa-private.pem`, 'utf-8'),
        passphrase: '123123',
      },
      // es: await fs.readFile(`${__dirname}/../keys/alpine-es256-private.pem`, 'utf-8'),
      hs: 'i-hope-that-you-change-this-long-default-secret-in-your-app',
    };

    await app.listen(4000, '0.0.0.0');
    // wait for haproxy backend keepalive
    await delay(1000);
  });

  beforeEach(async () => {
    await clearRedis(app.service);
    await app.service.consul.kv.del({
      key: keyPrefix,
      recurse: true,
    });
  });

  after(async () => {
    await app.close();
  });

  it('validates forged token', async () => {
    const res = await haGet('xx-yy-zz');
    validateResponse(res, {
      reason: 'E_TKN_INVALID',
      valid: '0',
      body: undefined,
    });
  });

  describe('HS', () => {
    it('validates valid token', async () => {
      const data = {
        username: '777444777',
        iat: Date.now(),
        exp: Date.now() + 30000,
        audience: ['x', 'y'],
        st: 1,
      };

      const res = await haGet(signHmac(data));
      validateResponse(res, {
        reason: 'ok',
        valid: '1',
        body: JSON.stringify(data),
      });
    });

    it('validates expired token', async () => {
      const data = {
        username: '777444777',
        iat: Date.now(),
        exp: Date.now() - 1000,
        audience: ['x', 'y'],
        st: 1,
      };

      const res = await haGet(signHmac(data));

      validateResponse(res, {
        valid: '0',
        reason: 'E_TKN_EXPIRE',
        body: JSON.stringify(data),
      });
    });
  });

  describe('RS', () => {
    it('validates valid token', async () => {
      const data = {
        username: '777444777',
        iat: Date.now(),
        exp: Date.now() + 30 * 24 * 60 * 60 * 1000,
        audience: ['x', 'y'],
        st: 1,
      };

      const token = signRsa(data);
      const res = await haGet(token);

      validateResponse(res, {
        valid: '1',
        reason: 'ok',
        body: JSON.stringify(data),
      });
    });

    it('validates expired token', async () => {
      const data = {
        username: '777444777',
        iat: Date.now(),
        exp: Date.now() - 1000,
        audience: ['x', 'y'],
        st: 1,
      };

      const res = await haGet(signRsa(data));

      validateResponse(res, {
        valid: '0',
        reason: 'E_TKN_EXPIRE',
        body: JSON.stringify(data),
      });
    });
  });

  describe('#rules', () => {
    let tid = 1;

    const base = {
      iss: 'ms-users',
      audience: '*.api',
      iat: Date.now(),
      exp: Date.now() + 30 * 24 * 60 * 60 * 1000,
      st: 1,
    };

    const createAccessToken = (rt, extra) => {
      tid += 1;
      return {
        cs: tid,
        st: 1,
        rt: rt.cs,
        username: rt.username,
        ...base,
        ...extra,
      };
    };

    const createRefreshToken = (username, extra) => {
      tid += 1;
      return {
        cs: tid,
        irt: 1,
        username,
        ...base,
        ...extra,
      };
    };

    const createTokenPair = (username, extra = {}) => {
      const refresh = createRefreshToken(username, extra);
      const access = createAccessToken(refresh);
      return { refresh, access };
    };

    const invRtRule = (rt) => {
      return JSON.stringify({
        _or: true, rt: rt.cs, cs: rt.cs, ttl: rt.exp,
      });
    };
    const invAll = (rt) => (JSON.stringify({ iat: { lte: Date.now() }, username: rt.username }));
    const invAccess = (newAccess) => (JSON.stringify({ rt: newAccess.rt, iat: { lt: newAccess.iat } }));

    const uRule = (rt) => rt.username;
    const gRule = () => 'g';

    describe('token-validation', () => {
      const user = 'foouser';

      before(async () => {
        await consulUtil.kvDel();
      });

      const blacklistedResponse = {
        valid: '0',
        reason: 'E_TKN_INVALID',
      };

      const okResponse = {
        valid: '1',
        reason: 'ok',
      };

      it('should validate tokens', async () => {
        const { revocationRulesManager } = app.service;

        const { refresh: firstRefresh, access: firstAccess } = createTokenPair(user);

        const secondAccess = createAccessToken(firstRefresh, {
          iat: Date.now() + 1 * 60 * 60 * 1000,
        });

        // invalidate 1 access token
        await revocationRulesManager.add(uRule(firstRefresh), invAccess(secondAccess));

        const thirdAccess = createAccessToken(firstRefresh, {
          iat: Date.now() + 2 * 60 * 60 * 1000,
        });

        // invalidate 2 access token
        await revocationRulesManager.add(uRule(firstRefresh), invAccess(thirdAccess));
        await delay(100);

        const thirdJwtRes = await haGet(signHmac(thirdAccess));
        const secondJwtRes = await haGet(signHmac(secondAccess));
        const firstJwtRes = await haGet(signHmac(firstAccess));

        validateResponse(firstJwtRes, blacklistedResponse);
        validateResponse(secondJwtRes, blacklistedResponse);
        validateResponse(thirdJwtRes, okResponse);

        // invalidate refresh token
        await revocationRulesManager.add(uRule(firstRefresh), invRtRule(firstRefresh));
        await delay(100);

        const thirdInvJwtRes = await haGet(signHmac(thirdAccess));
        const secondInvJwtRes = await haGet(signHmac(secondAccess));
        const firstInvJwtRes = await haGet(signHmac(firstAccess));

        validateResponse(firstInvJwtRes, blacklistedResponse);
        validateResponse(secondInvJwtRes, blacklistedResponse);
        validateResponse(thirdInvJwtRes, blacklistedResponse);
      });

      it('should validate tokens #global', async () => {
        const { revocationRulesManager } = app.service;

        // sign new tokens
        const newPair = createTokenPair(user);
        const newJwtRes = await haGet(signHmac(newPair.access));

        // invalidate all tokens
        await revocationRulesManager.add(gRule(), invAll(newPair.refresh));
        await delay(100);

        const newJwtBlockedRes = await haGet(signHmac(newPair.access));

        validateResponse(newJwtRes, okResponse);
        validateResponse(newJwtBlockedRes, blacklistedResponse);
      });

      it('#rules and #_or', async () => {
        const { revocationRulesManager } = app.service;

        const accessTokenData = createAccessToken({
          cs: 'xid',
          username: user,
          ...base,
        });

        await revocationRulesManager.add(uRule({ username: 'gt' }), JSON.stringify({ gtVal: { gt: 10 } }));
        await revocationRulesManager.add(uRule({ username: 'lt' }), JSON.stringify({ ltVal: { lt: 10 } }));
        await revocationRulesManager.add(uRule({ username: 'gte' }), JSON.stringify({ gteVal: { gte: 10 } }));
        await revocationRulesManager.add(uRule({ username: 'lte' }), JSON.stringify({ lteVal: { lte: 10 } }));

        await revocationRulesManager.add(uRule({ username: 'eq' }), JSON.stringify({ eqVal: { eq: 'some' } }));
        await revocationRulesManager.add(uRule({ username: 'eqNum' }), JSON.stringify({ eqVal: { eq: 10 } }));
        await revocationRulesManager.add(uRule({ username: 'eqString' }), JSON.stringify({ eqVal: 'some' }));

        await revocationRulesManager.add(uRule({ username: 'startsWith' }), JSON.stringify({ swVal: { sw: 'some' } }));

        await revocationRulesManager.add(uRule({ username: 'topLevelOr' }), JSON.stringify({
          _or: true,
          swVal: { sw: 'some' },
          eqVal: 'some',
        }));

        await revocationRulesManager.add(uRule({ username: 'operOr' }), JSON.stringify({
          swVal: {
            sw: 'some',
            _or: true,
            eq: 'foo',
          },
        }));

        await delay(100);

        const check = async (rule, data, shoulBeInvalid = true) => {
          const token = signHmac({
            ...accessTokenData,
            username: rule,
            ...data,
          });

          const response = await haGet(token);
          validateResponse(response, { valid: shoulBeInvalid ? '0' : '1' });
        };

        await check('gt', { gtVal: 10 }, false);
        await check('gt', { gtVal: 11 }, true);

        await check('lt', { ltVal: 10 }, false);
        await check('lt', { ltVal: 9 }, true);

        await check('gte', { gteVal: 9 }, false);
        await check('gte', { gteVal: 10 }, true);
        await check('gte', { gteVal: 11 }, true);

        await check('lte', { lteVal: 11 }, false);
        await check('lte', { lteVal: 10 }, true);
        await check('lte', { lteVal: 9 }, true);

        await check('eq', { eqVal: 'some' }, true);
        await check('eq', { eqVal: 'somex' }, false);

        await check('eqNum', { eqVal: 10 }, true);
        await check('eqNum', { eqVal: 11 }, false);

        await check('eqString', { eqVal: 'some' }, true);
        await check('eqString', { eqVal: 'somex' }, false);

        await check('startsWith', { swVal: 'someThatStarts' }, true);
        await check('startsWith', { swVal: 'xsomeThatNotStarts' }, false);

        await check('topLevelOr', { swVal: 'notsome', eqVal: 'some' }, true);
        await check('topLevelOr', { swVal: 'some', eqVal: 'neqsome' }, true);
        await check('topLevelOr', { swVal: 'notsome', eqVal: 'neqsome' }, false);

        await check('operOr', { swVal: 'somesss' }, true);
        await check('operOr', { swVal: 'foo' }, true);
        await check('operOr', { swVal: 'bar' }, false);
      });
    });
  });
});
