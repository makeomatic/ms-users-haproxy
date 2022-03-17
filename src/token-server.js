const { Microfleet, ConnectorsTypes } = require('@microfleet/core');
const { merge } = require('lodash');

const { ConsulWatcher, auth: { statelessJWT: { jwt, rule } } } = require('ms-users/src/utils');
const conf = require('./config');

const config = conf.get('/', { env: process.env.NODE_ENV });

const { RevocationRulesManager, RevocationRulesStorage } = rule;

class TokenServer extends Microfleet {
  constructor(opts = {}) {
    super(merge({}, config, opts));

    const pluginName = 'JwtRevocationRules';
    const { jwt: { stateless: { storage } } } = this.config;

    this.addConnector(ConnectorsTypes.application, () => {
      const { log, consul } = this;
      const watcher = new ConsulWatcher(consul, log);
      const ruleManager = this.revocationRulesManager = new RevocationRulesManager(this);
      const ruleStorage = this.revocationRulesStorage = new RevocationRulesStorage(
        ruleManager,
        watcher,
        storage,
        log
      );

      ruleStorage.startSync();
    }, pluginName);

    this.addDestructor(ConnectorsTypes.application, () => {
      this.revocationRulesStorage.stopSync();
    }, pluginName);
  }
}

/**
 * @api [POST] / Verify token
 * @apiDescription Verifies provided token using revocation rule filters
 */
const verifyRoute = {
  method: 'POST',
  url: '/',
  async handler(request) {
    const token = request.body;

    try {
      await jwt.verify(this.service, token);
      return 'ok';
    } catch (e) {
      if (![403, 401].includes(e.status)) {
        this.log.error({ error: e }, 'token verify error');
      }
      return e.code || e.message;
    }
  },
};

module.exports = {
  TokenServer,
  verifyRoute,
};
