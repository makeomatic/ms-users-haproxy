# HAPROXY JWT verification helper

Provides JWT token verification script for HAProxy and Service that performs token validation.

## Contents

<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=2 orderedList=false} -->

<!-- code_chunk_output -->

- [HAPROXY JWT verification helper](#haproxy-jwt-verification-helper)
  - [Contents](#contents)
  - [Supported algoritms](#supported-algoritms)
  - [Verification process](#verification-process)
  - [Token Server](#token-server)
  - [HaProxy `verify-jwt` script](#haproxy-verify-jwt-script)
  - [Request Headers and TXN vars](#request-headers-and-txn-vars)

<!-- /code_chunk_output -->

## Supported algoritms

* HMAC{any} - secret based signature verification
* RS/HS/ES{any} - public key verification

## Verification process

1. Verify the signature of the provided JWT token using the provided list of keys. Supports only `Authorization: JWT {token}` headers

2. Verify the token payload and expireation using the `token-server` sidecar.

## Token Server

Provides caching and validation logic for the token verification process.
Built on top of the `Microfleet`,`makeomatic/ms-users` and `Fastify`.
Used by the HaProxy LUA script as backend.

### Installation

Build and deploy container image from `Dockerfile.token-server` file.
Configure HaProxy backend to monitor and use this server.

```shell 
$@>: docker build -f ./Dockerfile.token-server -t token-server .
```

See `src/config` or `test/config` and consult https://github.com/microfleet/core for configuration examples.

## HaProxy `verify-jwt` script

### Installation

#### Manual
Copy `./src/lua` contents into `/usr/local/lib/lua/5.3/` and install dependencies.

**Dependencies**

```shell
> luarocks install lua-cjson 2.1.0-1;
> luarocks install LuaSocket;
> luarocks install luaossl;
```

#### DOCKER image

Or just use `Dockerfile` to `docker build` self-contained `haproxy` image.

```shell 
$@>: docker build -f ./Dockerfile -t haproxy-jwt .
```

#### Configuration

* `JWT_JWKS_FILE` - File that contains JWT verification keys.
* `JWT_JWKS_URL` - Url of the file that contains JWT verification keys.
* `JWT_SYNC_INTERVAL` - Seconds interval for the verification keys update.
* `JWT_CACHE_TTL` - Seconds to cache `token-server` response.
* `JWT_TOKEN_SERVER_BACKEND` - Backend that monitors `token-server`s and to resolve DNS to IP address.

##### Sample `haproxy.cfg`:

```conf
global
  setenv JWT_JWKS_FILE /usr/local/etc/haproxy/keys.json
  setenv JWT_JWKS_URL http://host/keys.json
  setenv JWT_SYNC_INTERVAL 400
  setenv JWT_CACHE_TTL 3
  setenv JWT_TOKEN_SERVER_BACKEND jwt-token-server

  lua-load /usr/local/lib/lua/5.3/verify-jwt.lua

listen fe_main
    bind :8080
    http-request lua.verify-jwt
    # ...

backend jwt-token-server
  # server s1 host.docker.internal:4000 check
  server s1 tester:4000 check inter 1s fall 5 rise 1

```

##### JWT Signing Keys

Set `JWT_JWKS_FILE` or `JWT_JWKS_URL` source. JWT signature verification keys should be provided using specific structure:

```json
// keys.json
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
* `x-tkn-reason` - `enum[E_TKN_*]` - validation result - see https://github.com/makeomatic/ms-users/src/constants.js errors
* `x-tkn-payload-*` - `token.body` contents
  **NOTE:** Due to LUA implementations all numbers passed as `floats`.

And additional variables added to the HaProxy `TXN` scope:

* `txn.tkn.valid`
* `txn.tkn.reason`
* `txn.tkn.payload.*`
