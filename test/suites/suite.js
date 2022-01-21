const fs = require('fs').promises
const { deepStrictEqual } = require('assert')
const { delay } = require('bluebird')

const axios = require("axios").default
const Consul = require("consul")
const ld = require('lodash')

const jwt = require('jsonwebtoken')

const haServer = "http://haproxy:8080"
const consulServer = "consul"
const keyPrefix = "microfleet/ms-users/revocation-rules"

axios.defaults.baseURL = haServer

const consul = new Consul({
  host: consulServer,
  promisify: true,
});

const kvGet = (extra = '') => {
  return consul.kv.get({
    recurse: true,
    key: `${keyPrefix}/${extra}`,
  })
}

const kvPut = (key, data) => {
  return consul.kv.set(`${keyPrefix}/${key}`, JSON.stringify(data))
}

const kvDel = (key = '') => {
  return consul.kv.del({
    key: `${keyPrefix}/${key}`,
    recurse: true,
  })
}

const haGet = async (token) => {
  const response = await axios.get('/', {
    headers: {
      'authorization': token ? `JWT ${token}` : undefined
      // 'Authorization': token ? `Bearer ${token}` : undefined
    },
  })
  const interesting = Object.keys(response.data).filter((p) => p.startsWith('x-'))

  return ld.pick(response.data, interesting)
}

describe('HaProxy lua', () => {
  let privateKeys
  
  const signRsa = (payload) => jwt.sign({ ...payload }, privateKeys.rsa, { algorithm: 'RS256' })
  // const signEs = (payload) => jwt.sign({ ...payload }, privateKeys.es, { algorithm: 'ES256' })
  const signHmac = (payload) => jwt.sign({ ...payload }, privateKeys.hs, { algorithm: 'HS256' })

  const validateResponse = (res, expected) => {
    const prefix = 'x-tkn';
    Object.entries(expected).forEach(([k, v]) => {
      const prop = `${prefix}-${k}`
      deepStrictEqual(res[prop], v, `header '${prop}' should have value '${v}' but has '${res[prop]}'`)
    })  
  }

  before(async () => {
    privateKeys = {
      rsa: {
        key: await fs.readFile(`${__dirname}/../keys/rsa-private.pem`, 'utf-8'),
        passphrase: '123123'
      },
      // es: await fs.readFile(`${__dirname}/../keys/alpine-es256-private.pem`, 'utf-8'),
      hs: 'i-hope-that-you-change-this-long-default-secret-in-your-app'
    }
  })

  describe('HS', () => {
    it('validates valid token', async () => {
      const data = {
        username: '777444777',
        iat: Date.now(),
        exp: Date.now()+30000,
        audience: [ 'x', 'y']
      }

      const res = await haGet(signHmac(data))

      validateResponse(res, {
        reason: 'ok',
        valid: '1',
        'payload-username': '777444777',
        'payload-audience': '["x","y"]',
        'payload-iat': `${data.iat}.0`,
        'payload-exp': `${data.exp}.0`,
      })
    });

    it('validates expired token', async () => {
      const data = {
        username: '777444777',
        iat: Date.now(),
        exp: Date.now() - 1000,
        audience: [ 'x', 'y']
      }

      const res = await haGet(signHmac(data))

      validateResponse(res, {
        valid: '0',
        reason: 'expired',
        'payload-username': '777444777',
        'payload-audience': '["x","y"]',
        'payload-iat': `${data.iat}.0`,
        'payload-exp': `${data.exp}.0`,
      })
    });
  });

  describe('RS', () => {
    it('validates valid token', async () => {
      const data = {
        username: '777444777',
        iat: Date.now(),
        exp: Date.now() + 30 * 24 * 60 * 60 * 1000,
        audience: ['x', 'y']
      }

      const token = signRsa(data)
      const res = await haGet(token)

      validateResponse(res, {
        valid: '1',
        reason: 'ok',
        'payload-iat': `${data.iat}.0`,
        'payload-exp': `${data.exp}.0`,
        'payload-audience': '["x","y"]',
        'payload-username': '777444777'
      })
    });
    
    it('validates expired token', async () => {
      const data = {
        username: '777444777',
        iat: Date.now(),
        exp: Date.now() - 1000,
        audience: [ 'x', 'y']
      }

      const res = await haGet(signRsa(data))

      validateResponse(res, {
        valid: '0',
        reason: 'expired',
        'payload-iat': `${data.iat}.0`,
        'payload-exp': `${data.exp}.0`,
        'payload-audience': '["x","y"]',
        'payload-username': '777444777'
      })
    });
  });

  describe('#rules', () => {
    let tid = 1;

    const base = {
      iss: 'ms-users',
      audience: "*.api",
      iat: Date.now(),
      exp: Date.now() + 30 * 24 * 60 * 60 * 1000,
    }

    const createAccessToken = (rt, extra) => {
      tid++;
      return {
        cs: tid, st: 1, rt: rt.cs,
        username: rt.username,
        ...base, ...extra,
      }
    }

    const createRefreshToken = (username, extra) => {
      tid++;
      return {
        cs: tid, irt: 1, username,
        ...base, ...extra,
      }
    }

    const createTokenPair = (username, extra = {}) => {
      const refresh = createRefreshToken(username, extra)
      const access = createAccessToken(refresh)
      return { refresh, access }
    }

    const invRtRule = (rt) => ({ _or: true, rt: rt.cs, cs: rt.cs });
    const invAll = (rt) => ({ iat: { lte: Date.now() }, username: rt.username });
    const invAccess = (newAccess) => ({ rt: newAccess.rt, iat: { lt: newAccess.iat }, });

    const uRule = (rt) => `u/${rt.username}/${tid++}`;
    const gRule = () => `g/${tid++}`;

    describe('token-validation', () => {
      const user = 'foouser';

      before(async () => {
        await kvDel()
      })

      const blacklistedResponse = {
        valid: '0',
        reason: 'blacklisted',
        'payload-iss': 'ms-users',
        'payload-username': user
      }

      const okResponse = {
        valid: '1',
        reason: 'ok',
        'payload-iss': 'ms-users',
        'payload-username': user
      }

      it('should validate tokens', async () => {
        const { refresh: firstRefresh, access: firstAccess } = createTokenPair(user);
        
        const secondAccess = createAccessToken(firstRefresh, {
          iat: Date.now() + 1 * 60 * 60 * 1000,
        })
  
        // invalidate 1 access token
        await kvPut(uRule(firstRefresh), invAccess(secondAccess));
  
        const thirdAccess = createAccessToken(firstRefresh, {
          iat: Date.now() + 2 * 60 * 60 * 1000,
        })
  
        // invalidate 2 access token
        await kvPut(uRule(firstRefresh), invAccess(thirdAccess));
        await delay(2000);
  
        const thirdJwtRes = await haGet(signHmac(thirdAccess));
        const secondJwtRes = await haGet(signHmac(secondAccess));
        const firstJwtRes = await haGet(signHmac(firstAccess));
  
  
        validateResponse(firstJwtRes, blacklistedResponse)
        validateResponse(secondJwtRes, blacklistedResponse)
        validateResponse(thirdJwtRes, okResponse)
  
        // invalidate refresh token
        await kvPut(uRule(firstRefresh), invRtRule(firstRefresh));
        await delay(2000);
  
        const thirdInvJwtRes = await haGet(signHmac(thirdAccess));
        const secondInvJwtRes = await haGet(signHmac(secondAccess));
        const firstInvJwtRes = await haGet(signHmac(firstAccess));
  
        validateResponse(firstInvJwtRes, blacklistedResponse)
        validateResponse(secondInvJwtRes, blacklistedResponse)
        validateResponse(thirdInvJwtRes, blacklistedResponse)
      })

      it('should validate tokens #global', async () => {
        // sign new tokens
        const newPair = createTokenPair(user);
        const newJwtRes = await haGet(signHmac(newPair.access));
  
        // invalidate all tokens
        await kvPut(gRule(), invAll(newPair.refresh));
        await delay(2000);
  
        const newJwtBlockedRes = await haGet(signHmac(newPair.access));

        validateResponse(newJwtRes, okResponse)
        validateResponse(newJwtBlockedRes, blacklistedResponse)
      })

      it('#rules and #_or', async () => {
        const accessTokenData = createAccessToken({
          cs: 'xid',
          username: user,
          ...base,
        })

        await kvPut(uRule({ username: 'gt' }), { gtVal: { gt: 10 }})
        await kvPut(uRule({ username: 'lt' }), { ltVal: { lt: 10 }})
        await kvPut(uRule({ username: 'gte' }), { gteVal: { gte: 10 }})
        await kvPut(uRule({ username: 'lte' }), { lteVal: { lte: 10 }})

        await kvPut(uRule({ username: 'eq' }), { eqVal: { eq: 'some' }})
        await kvPut(uRule({ username: 'eqNum' }), { eqVal: { eq: 10 }})
        await kvPut(uRule({ username: 'eqString' }), { eqVal: 'some' })
        
        await kvPut(uRule({ username: 'match' }), { matchVal: { match : 'some777some' } })
        await kvPut(uRule({ username: 'startsWith' }), { swVal: { sw: 'some' }})

        await kvPut(uRule({ username: 'topLevelOr' }), {
          _or: true,
          swVal: { sw: 'some' },
          eqVal: 'some'
        })

        await kvPut(uRule({ username: 'operOr' }), {
          swVal: {
            sw: 'some',
            _or: true,
            eq: 'foo'
          },
        })

        await delay(2000)

        const check = async (rule, data, shoulBeInvalid = true) => {
          const token = signHmac({
            ...accessTokenData,
            username: rule,
            ...data
          })

          const response = await haGet(token)
          validateResponse(response, { valid: shoulBeInvalid ? '0' : '1' })
        }
        
        await check('gt', { gtVal: 10 }, false)
        await check('gt', { gtVal: 11 }, true)
        
        await check('lt', { ltVal: 10 }, false)
        await check('lt', { ltVal:  9}, true)

        await check('gte', { gteVal: 9 }, false)
        await check('gte', { gteVal: 10 }, true)
        await check('gte', { gteVal: 11 }, true)

        await check('lte', { lteVal: 11 }, false)
        await check('lte', { lteVal: 10 }, true)
        await check('lte', { lteVal:  9}, true)

        await check('eq', { eqVal: 'some' }, true)
        await check('eq', { eqVal: 'somex' }, false)

        await check('eqNum', { eqVal: 10 }, true)
        await check('eqNum', { eqVal: 11 }, false)

        await check('eqString', { eqVal: 'some' }, true)
        await check('eqString', { eqVal: 'somex' }, false)

        await check('match', { matchVal: 'xbarsome777somexbar' }, true)
        await check('match', { matchVal: 'xbarsomexbar' }, false)

        await check('startsWith', { swVal: 'someThatStarts' }, true)
        await check('startsWith', { swVal: 'xsomeThatNotStarts' }, false)

        await check('topLevelOr', { swVal: 'notsome', eqVal: 'some' },  true)
        await check('topLevelOr', { swVal: 'some', eqVal: 'neqsome' },  true)
        await check('topLevelOr', { swVal: 'notsome', eqVal: 'neqsome' },  false)

        await check('operOr', { swVal: 'somesss' }, true)
        await check('operOr', { swVal: 'foo' },  true)
        await check('operOr', { swVal: 'bar' },  false)
      })
    })
  })
});
