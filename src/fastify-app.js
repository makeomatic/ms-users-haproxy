const fastify = require('fastify');
const fp = require('fastify-plugin');
const { PLUGIN_STATUS_FAIL } = require('@microfleet/core');

const { TokenServer, verifyRoute } = require('./token-server');

const app = fastify({ logger: true });

const plugin = fp(async function plugin(instance) {
  const service = new TokenServer();

  instance.decorate('service', service);
  instance.addHook('onClose', async () => {
    if (service) {
      await service.close();
    }
  });
  await service.connect();

  instance.log.level = service.log.level;
});

app.addContentTypeParser('*', { parseAs: 'string' }, app.getDefaultJsonParser('ignore', 'ignore'));
app.register(plugin);

app.route(verifyRoute);
app.route({
  method: 'GET',
  url: '/generic/health',
  async handler() {
    const data = await this.service.getHealthStatus();
    if (PLUGIN_STATUS_FAIL === data.status) {
      const err = new Error('unhealthy');
      err.data = data;
    }

    return data;
  },
});

module.exports = app;
