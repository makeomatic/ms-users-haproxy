# HAPROXY JWT verification

Provides JWT token verification script for HAProxy.

**Supported algoritms:**

* HMAC{any} - secret based signature verification
* RS/HS/ES{any} - public key verification

### Verification process

1. Verify the signature of the provided JWT token using the provided list of keys.
2. Verify the expiration time of the token using `exp` field.
3. Verify the token payload using the Revocation list.

## Installation

Copy `./lua` contents into `/usr/local/lib/lua/5.3/` and install dependencies.

### Dependencies

```shell
> luarocks install lua-cjson 2.1.0-1;
> luarocks install LuaSocket;
> luarocks install luaossl;
> luarocks install --server=http://luarocks.org/dev lua-consul;
```

### DOCKER

Or just use `Dockerfile` to `docker build` self-contained `haproxy` image.

### Configuration

* `CONSUL_ADDR` - The Consul server address.
* `CONSUL_KEY_PREFIX` - The Consul KV path for the Revocation rules list.
* `CONSUL_SYNC_INTERVAL` - Seconds interval for the Recocation rules list update.
* `JWT_JWKS_FILE` - File that contains JWT verification keys.
* `JWT_JWKS_URL` - Url of the file that contains JWT verification keys.
* `JWT_SYNC_INTERVAL` - Seconds interval for the verification keys update.

Sample `haproxy.cfg`:

```
global
  lua-load /usr/local/lib/lua/5.3/verify-jwt.lua

  setenv CONSUL_ADDR consul:8500
  setenv CONSUL_KEY_PREFIX microfleet/ms-users/revocation-rules
  setenv CONSUL_SYNC_INTERVAL 400
  setenv JWT_JWKS_FILE /usr/local/etc/haproxy/keys.json
  setenv JWT_JWKS_URL http://host/keys.json
  setenv JWT_SYNC_INTERVAL 400

listen fe_main
    bind :8080
    http-request lua.verify-jwt
    # ...
```

## Keys

JWT signature verification keys should be provided using specific structure:

```json
[
  {
    "kid": "keyID",
    "secret": "your-super-secure-secret" 
  },
  {
    "kid": "keyID",
    "cert": "contents of the public key" 
  }
]
```

## Request Headers and TXN vars

Script appends additional request headers after token validation process:

* `x-tkn-valid` - `enum[0, 1]` - signature validation result. `1` == success
* `x-tkn-reason` - `enum[ok, absent, forged, blacklisted]` - validation result
* `x-tkn-payload-*` - `token.body` contents

And additional variables added to the HaProxy `TXN` scope:

* `txn.tkn.valid`
* `txn.tkn.reason`
* `txn.tkn.payload.*`
