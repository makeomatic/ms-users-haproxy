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
      console.debug(res)

      deepStrictEqual(res, {
        'x-tkn-payload-iat': `${data.iat}.0`,
        'x-tkn-payload-exp': `${data.exp}.0`,
        'x-tkn-valid': '1',
        'x-tkn-payload-audience': '["x","y"]',
        'x-tkn-reason': 'ok',
        'x-tkn-payload-username': '777444777'
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
      console.debug(res)

      deepStrictEqual(res, {
        'x-tkn-payload-iat': `${data.iat}.0`,
        'x-tkn-payload-exp': `${data.exp}.0`,
        'x-tkn-valid': '0',
        'x-tkn-payload-audience': '["x","y"]',
        'x-tkn-reason': 'expired',
        'x-tkn-payload-username': '777444777'
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
      console.debug({ token })
      const res = await haGet(token)

      console.debug(res);
      deepStrictEqual(res, {
        'x-tkn-payload-iat': `${data.iat}.0`,
        'x-tkn-payload-exp': `${data.exp}.0`,
        'x-tkn-valid': '1',
        'x-tkn-payload-audience': '["x","y"]',
        'x-tkn-reason': 'ok',
        'x-tkn-payload-username': '777444777'
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
      console.debug(res)
      deepStrictEqual(res, {
        'x-tkn-payload-iat': `${data.iat}.0`,
        'x-tkn-payload-exp': `${data.exp}.0`,
        'x-tkn-valid': '0',
        'x-tkn-payload-audience': '["x","y"]',
        'x-tkn-reason': 'expired',
        'x-tkn-payload-username': '777444777'
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

    it.only('should validate tokens', async () => {
      await kvDel()
      
      const u1 = 'foouser';
      const { refresh: firstRefresh, access: firstAccess } = createTokenPair(u1);
      
      const secondAccess = createAccessToken(firstRefresh, {
        iat: Date.now() + 1 * 60 * 60 * 1000,
      })

      await kvPut(uRule(firstRefresh), invAccess(secondAccess));

      const thirdAccess = createAccessToken(firstRefresh, {
        iat: Date.now() + 2 * 60 * 60 * 1000,
      })

      await kvPut(uRule(firstRefresh), invAccess(thirdAccess));

      await delay(3000);

      const res = await haGet(signHmac(thirdAccess));
      const res2 = await haGet(signHmac(secondAccess));
      const res3 = await haGet(signHmac(firstAccess));

      console.debug({
        res, res2, res3
      })

      await kvPut(uRule(firstRefresh), invRtRule(firstRefresh));

      await delay(3000);

      const ares = await haGet(signHmac(thirdAccess));
      const ares2 = await haGet(signHmac(secondAccess));
      const ares3 = await haGet(signHmac(firstAccess));

      console.debug({
        ares, ares2, ares3
      })

      const newPair = createTokenPair(u1);
      const bres = await haGet(signHmac(newPair.access));
      
      await kvPut(gRule(), invAll(newPair.refresh));
      
      await delay(3000);

      const bres2 = await haGet(signHmac(newPair.access));
      console.debug({
        bres, bres2
      })
    })
  })
});
