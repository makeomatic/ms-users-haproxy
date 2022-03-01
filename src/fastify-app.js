const fastify = require('fastify');
const fp = require('fastify-plugin');

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

module.exports = app;
