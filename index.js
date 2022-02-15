const app = require('./src/token-server');

const start = async () => {
  try {
    await app.listen(4000, '0.0.0.0');
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();