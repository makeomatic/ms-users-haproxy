exports = module.exports = {};

/**
 * @typedef {import("@microfleet/core").Microfleet} Microfleet
 * @param {Microfleet} service
 */
exports.clearRedis = async (service) => {
  if (service.redisType === 'redisCluster') {
    await Promise.map(service.redis.nodes('master'), (node) => (
      node.flushdb()
    ));
  } else {
    await service.redis.flushdb();
  }
};
