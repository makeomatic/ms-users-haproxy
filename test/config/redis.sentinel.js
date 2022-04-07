exports.redis = {
  sentinels: [{
    host: 'redis-sentinel',
    port: 26379,
  }],
  name: 'mservice',
  options: {},
};

exports.plugins = ['logger', 'validator', 'consul', 'redisSentinel'];
