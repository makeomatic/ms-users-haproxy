const { Microfleet, ConnectorsTypes } = require('@microfleet/core');
const { merge } = require('lodash');

const { ConsulWatcher, auth: { statelessJWT: { jwt, rule, jwe: { JoseWrapper } } } } = require('ms-users/src/utils');
const conf = require('./config');

const config = conf.get('/', { env: process.env.NODE_ENV });

const { RevocationRulesManager, RevocationRulesStorage } = rule;

class TokenServer extends Microfleet {
  constructor(opts = {}) {
    super(merge({}, config, opts));

    const pluginName = 'JwtRevocationRules';
    const { jwt: { stateless: { storage, jwe } } } = this.config;

    this.addConnector(ConnectorsTypes.application, async () => {
      const { log, consul } = this;
      const watcher = new ConsulWatcher(consul, log);
      this.jwe = new JoseWrapper(jwe);
      await this.jwe.init();

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
    const rawToken = request.body;
    this.log.debug({ rawToken }, '=== RAW');

    if (!JoseWrapper.isJweToken(rawToken)) {
      return {
        valid: '0',
        legacy: '1',
        reason: 'E_TKN_LEGACY',
      };
    }

    try {
      const { service } = this;
      const { payload, protectedHeader } = await service.jwe.decrypt(rawToken);
      const verifiedToken = await jwt.verify(service, payload);

      return {
        valid: '1',
        reason: 'ok',
        body: verifiedToken,
        header: protectedHeader,
        stateless: '1',
      };
    } catch (e) {
      if (![403, 401].includes(e.status)) {
        this.log.error({ error: e }, 'token verify error');
      }

      return {
        valid: '0',
        reason: e.code || e.message,
        stateless: '1',
      };
    }
  },
};

module.exports = {
  TokenServer,
  verifyRoute,
};
