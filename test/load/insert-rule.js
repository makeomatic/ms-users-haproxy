/* eslint-disable no-await-in-loop */
const { delay } = require('bluebird');

const ConsulUtil = require('../util/consul');

const consulServer = 'localhost';
const keyPrefix = 'microfleet/ms-users/revocation-rules';
const consulUtil = new ConsulUtil({ host: consulServer }, keyPrefix);

let cnt = 0;
async function start() {
  // eslint-disable-next-line no-constant-condition
  while (true) {
    await delay(1000);
    await consulUtil.kvPut(`u/dumb/r-${cnt}`, {
      username: 'dumb',
      rt: '2020',
    });
    cnt += 1;
  }
}

start()
  .then(() => { console.debug('Done'); })
  .catch((err) => {
    console.debug(
      'x',
      require('util').inspect(err, { depth: null, colors: true })
    );
  });
