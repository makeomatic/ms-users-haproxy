const fs = require('fs').promises;

const { map } = require('bluebird');
const ld = require('lodash');
const Redis = require('ioredis');

const jwt = require('jsonwebtoken')


const ruleCount = 100;
let total = 0;

function createGlobalCmds(r) {
  const gKey = JSON.stringify({
    _or: true,
    cs: `g-${r}`,
    rt: 'g-0',
    iat: {
      lte: 777777,
      gte: 111111,
    },
    aud: {
      match: 'no-match',
      _or: true,
      eq: 'x-no-start',
    },
  });

  return {
    key: 'rules:g', value: gKey,
  };
}

function createUserCmds(userId, r) {
  const uKey = JSON.stringify({
    _or: true,
    cs: `${userId}-${r}`,
    rt: `${userId}-0`,
    iat: {
      lte: 777777,
      gte: 111111,
    },
    aud: {
      match: 'no-match',
      _or: true,
      eq: 'x-no-start',
    },
  });

  return {
    key: `rules:u:${userId}`,
    value: uKey,
  };
}

async function createGlobalRules(redis) {
  const globalPairs = [];

  ld.range(0, ruleCount).forEach((r) => {
    const { key, value } = createGlobalCmds(r);
    globalPairs.push(['zadd', key, Date.now(), value]);
  });

  const chunks = ld.chunk(globalPairs, 60);

  await map(chunks, async (chunk) => {
    total += chunk.length;
    const pipeline = redis.multi(chunk);
    await pipeline.exec();
  }, { concurrency: 10 });
}

async function createUserRules(redis, userIds = []) {
  await map(userIds, async (userId) => {
    const pairs = [];
    ld.range(0, ruleCount).forEach((r) => {
      const { key, value } = createUserCmds(userId, r);
      pairs.push(['zadd', key, Date.now(), value]);
    });

    const chunks = ld.chunk(pairs, 60);

    await map(chunks, async (chunk) => {
      total += chunk.length;
      const pipeline = redis.multi(chunk);
      await pipeline.exec();
    }, { concurrency: 5 });
  }, {
    concurrency: 8,
  });
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
  const rendered = tokens.map((token) => `[Authorization: JWT ${token}]\n/\n`).join('')
  await fs.writeFile(`${__dirname}/ammo.txt`, rendered)
}

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

async function start() {
  const redis = new Redis({
    sentinels: [
      { host: 'redis-sentinel', port: 26379 },
    ],
    name: 'mservice',
  });
  privateKeys = await loadKeys()

  const users = [];

  ld.range(3000).forEach((i) => {
    users.push(`foo-${i}`, `bar-${i}`, `baz-${i}`);
  });

  console.debug('Create tokens')
  const userTokens = await createTokens(users)

  console.debug('Create rules...');

  const fn = setInterval(() => {
    console.debug(`Created ${total} rules`);
  }, 5000);

  await createGlobalRules(redis);

  console.debug('GLOBAL CREATED');

  await createUserRules(redis, users);
  console.debug('USER CREATED');

  clearInterval(fn);

  console.debug('Done Create rules...');

  console.debug('tokens', userTokens.map((t) => `curl --header "Authorization: JWT ${t}" localhost:8080`))

  await createConfig()
  await createAmmo(userTokens)
  
  redis.disconnect();
}

start()
  .then(() => { console.debug('Done'); return 1; })
  .catch((err) => {
    console.debug('x',
      require('util').inspect(err, { depth: null, colors: true }));
  });
