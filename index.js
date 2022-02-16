const app = require('./src/token-server');

const start = async () => {
  try {
    await app.listen(process.env.PORT || 4000, '0.0.0.0');
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();
