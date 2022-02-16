module.exports = {
  name: "token-server",
  plugins: ["logger", "validator", "consul"],
  logger: {
    debug: false,
    defaultLogger: true,
  },
  consul: {
    base: {
      host: 'consul',
    },
  },
  jwt: {
    stateless: {
      enabled: true,
      storage: {
        watchOptions: {},
        storageCacheTTL: 7 * 1000,
      }
    }
  }
}