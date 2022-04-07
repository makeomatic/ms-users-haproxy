const dbSrv = process.env.DB_SRV || "redisSentinel";
const repo = process.env.DOCKER_REPO || 'makeomatic';
const node = '16';
const version = process.env.IMAGE_VERSION || process.env.npm_package_version;

exports = module.exports = {
  node,
  auto_compose: true,
  repo,
  services: [],
  with_local_compose: true,
  nycCoverage: false,
  sleep: 5,
  rebuild: ['ms-flakeless'],
  extras: {
    tester: {
      volumes: ['${PWD}/test/config:/configs:cached'],
      expose: ['4000'],
      environment: {
        NODE_ENV: "test",
        DB_SRV: dbSrv,
        CI: "${CI:-}",
        DEBUG: "${DEBUG:-''}",
        NCONF_NAMESPACE: 'MS_USERS_TOKEN_SERVER',
      },
    },
  },
  version,
  dba: {
    HAPROXY_IMAGE_NAME: `${repo}/haproxy`,
    HAPROXY_IMAGE_VERSION: version
  },
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
