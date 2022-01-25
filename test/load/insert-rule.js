const fs = require('fs').promises
const jwt = require('jsonwebtoken')
const { map, delay } = require('bluebird')
const ld = require('lodash')

const ConsulUtil = require('../util/consul')

const consulServer = "localhost"
const keyPrefix = "microfleet/ms-users/revocation-rules"
const consulUtil = new ConsulUtil({ host: consulServer }, keyPrefix)


async function start() {
  while (true) {
    await delay(300);
    await consulUtil.kvPut('u/dumb', {
      username: 'dumb',
      rt: '2020'
    })
  }
}

start()
  .then(() => { console.debug('Done') })
  .catch((err) => {
    console.debug('x',
      require('util').inspect(err, { depth: null, colors: true})
    )
  })