module.exports = {
  name: "token-server",
  plugins: ["logger", "validator", "consul"],
  logger: {
    debug: true,
    defaultLogger: true,
  },
  consul: {
    base: {
      host: 'consul',
      // we should probably deny access to setting this config variable from outside of the service,
      // because it depends on how does the code work
      promisify: true,
    },
  },
  jwt: {
    stateless: {
      enabled: true,
      storage: {
        watchOptions: {},
      }
    }
  }
}