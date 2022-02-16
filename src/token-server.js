const fastify = require('fastify');
const fp = require('fastify-plugin');

const { Microfleet, ConnectorsTypes } = require('@microfleet/core');
const { merge } = require('lodash');
const { ConsulWatcher } = require('ms-users/src/utils/consul-watcher');
const { RevocationRulesManager } = require('ms-users/src/utils/revocation-rules-manager');
const { RevocationRulesStorage } = require('ms-users/src/utils/revocation-rules-storage');
const { verify } = require('ms-users/src/utils/jwt-stateless');

const conf = require('./config');

const config = conf.get('/', { env: process.env.NODE_ENV });

class Essential extends Microfleet {
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

const app = fastify({ logger: true });

const plugin = fp(async function (instance) {
  const service = new Essential();

  instance.decorate('service', service);
  instance.addHook('onClose', async () => {
    if (service) {
      await service.close();
    }
  })
  await service.connect();

  instance.log.level = service.log.level;
})

app.register(plugin);
app.addContentTypeParser('*', { parseAs: 'string' }, app.getDefaultJsonParser('ignore', 'ignore'));

app.route({
  method: 'POST',
  url: '/',
  handler: async function (request) {
    const token = request.body;

    try {
      await verify(this.service, token);
      return 'ok';
    } catch (e) {
      return e.code || 'unk';
    }
  },
});

module.exports = app;