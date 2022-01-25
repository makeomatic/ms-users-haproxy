const fs = require('fs').promises
const jwt = require('jsonwebtoken')
const { map } = require('bluebird')
const ld = require('lodash')

const ConsulUtil = require('../util/consul')

const consulServer = "localhost"
const keyPrefix = "microfleet/ms-users/revocation-rules"
const consulUtil = new ConsulUtil({ host: consulServer }, keyPrefix)


const signRsa = (payload) => jwt.sign({ ...payload }, privateKeys.rsa, { algorithm: 'RS256' })
const signHmac = (payload) => jwt.sign({ ...payload }, privateKeys.hs, { algorithm: 'HS256' })

async function loadKeys() {
  return {
    rsa: {
      key: await fs.readFile(`${__dirname}/../keys/rsa-private.pem`, 'utf-8'),
      passphrase: '123123'
    },
    // es: await fs.readFile(`${__dirname}/../keys/alpine-es256-private.pem`, 'utf-8'),
    hs: 'i-hope-that-you-change-this-long-default-secret-in-your-app'
  }
}

const ruleCount = 5
let privateKeys;
let total = 0;

function createCmds(userId, r) {
  const uKey = JSON.stringify({
    _or: true,
    cs: `${userId}-${r}`,
    rt: `${userId}-0`,
    iat: {
      lte: 777777,
      gte: 111111
    },
    aud: {
      match: "no-match",
      _or: true,
      sw: "x-no-start"
    }
  })

  const gKey = JSON.stringify({
    _or: true,
    cs: `g-${r}`,
    rt: 'g-0',
    iat: {
      lte: 777777,
      gte: 111111
    },
    aud: {
      match: "no-match",
      _or: true,
      sw: "x-no-start"
    }
  })

  return [
    {
      KV: {
        Verb: 'set',
        Key: `microfleet/ms-users/revocation-rules/u/${userId}/${userId}-${r}`,
        Value: Buffer.from(uKey).toString('base64')
      } 
    }, {
      KV: {
        Verb: 'set',
        Key: `microfleet/ms-users/revocation-rules/g/${r}`,
        Value: Buffer.from(gKey).toString('base64')
      } 
    }
  ]
}

async function createUserRules(userIds = []) {
  await consulUtil.kvDel()
  console.debug('RULES DELETED')
  

  await map(userIds, async (userId) => {
    const pairs = []
    ld.range(0, ruleCount).forEach((r) => {
      pairs.push(
        ... createCmds(userId, r)
      )
    })

    const chunks = ld.chunk(pairs, 30)

    await map(chunks, async (chunk) => {
      total += chunk.length
      await consulUtil.consul.transaction.create(chunk)
    }, { concurrency: 5 })
  }, {
    concurrency: 4,
  })
}

function createTokens(users) {
  const exp = Date.now() + 30 *24 * 60 * 60 * 1000
  return users.map((user) => signRsa({
    cs: `${user}-0xx`,
    rt: `${user}-0xx`,
    exp,
    iat: 777777776,
    username: user,
    iss: 'ms-users',
    extra: true,
  }))
}

async function createConfig(token) {
  const template = await fs.readFile(`${__dirname}/load.yaml.template`, 'utf-8');
  const rendered = template.replace(/{token}/, token)
  await fs.writeFile(`${__dirname}/load.yaml`, rendered);
}

async function createAmmo(tokens) {
  const rendered = tokens.map((token) => `[Authorization: JWT ${token}]\n/\n`)
  await fs.writeFile(`${__dirname}/ammo.txt`, rendered)
}

async function start() {
  privateKeys = await loadKeys()
  const users = []

  ld.range(20000).forEach((i) => {
    users.push(`foo-${i}`, `bar-${i}`, `baz-${i}`)
  })
  
  console.debug('Create tokens')
  const userTokens = await createTokens(users)

  console.debug('Create rules...')
  
  const fn = setInterval(() => {
    console.debug(`Created ${total} rules`)
  }, 5000)
  
  await createUserRules(users)
  
  clearInterval(fn)

  console.debug('Done Create rules...') 
  console.debug('tokens', userTokens)

  await createConfig()
  await createAmmo(userTokens)
}

start()
  .then(() => { console.debug('Done') })
  .catch((err) => {
    console.debug('x',
      require('util').inspect(err, { depth: null, colors: true})
    )
  })