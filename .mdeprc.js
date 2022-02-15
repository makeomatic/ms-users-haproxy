const dbSrv = process.env.DB_SRV || "redisSentinel";

exports = module.exports = {
  node: '16',
  auto_compose: true,
  services: [],
  with_local_compose: true,
  nycCoverage: false,
  extras: {
    tester: {
      volumes: ['${PWD}/test/config:/configs:cached'],
      expose: ['4000'],
      environment: {
        NODE_ENV: "test",
        DB_SRV: dbSrv,
        CI: "${CI:-}",
        DEBUG: "${DEBUG:-''}",
        NCONF_NAMESPACE: 'MS_USERS_HAPROXY',
      },
    },
  }
};


switch (dbSrv) {
  case 'redisCluster':
    exports.services = ['redisCluster'];
    exports.extras.tester.environment.NCONF_FILE_PATH = '["/configs/core.js","/configs/redis.cluster.js"]';
    
    break;
  case 'redisSentinel':
    exports.services = ['redisSentinel'];
    exports.extras.tester.environment.NCONF_FILE_PATH = '["/configs/core.js","/configs/redis.sentinel.js"]';
    break;
}
