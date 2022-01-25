const Consul = require('consul')

class ConsulUtil {
  constructor({ host = 'consul', port = '8500'}, keyPrefix) {
    this.keyPrefix = keyPrefix;
    this.consul = new Consul({
      host,
      port,
      promisify: true,
      defaults: {
        timeout: 35000,
      }
    });
  }

  kvGet(extra = '') {
    return this.consul.kv.get({
      recurse: true,
      key: `${this.keyPrefix}/${extra}`,
    })
  }
  
  kvPut(key, data) {
    return this.consul.kv.set(`${this.keyPrefix}/${key}`, JSON.stringify(data))
  }
  
  kvDel(key = '') {
    return this.consul.kv.del({
      key: `${this.keyPrefix}/${key}`,
      recurse: true,
    })
  }
}

module.exports = ConsulUtil