local cjson = require("cjson.safe")

require "verify-jwt.print_r"

local jwks = require "verify-jwt.jwks"
local config = require "verify-jwt.config"
local socket = require "socket"

local newCjson = cjson.new
local JWT_CACHE_TTL = config.jwt.cacheTTL
local JWT_TOKEN_SERVER_BACKEND = config.jwt.tokenServer

local verifyCache = {}

-- Extracts JWT token information using haproxy internal features
-- parses header and body using `cjson` library
local function extractJWTFromHeader(txn)
  local authHeader = txn.f:req_fhdr('authorization')

  if authHeader == nil then
    return nil
  end

  local headerProps = core.tokenize(authHeader or "", " ")

  local tokenType = headerProps[1]
  local jwtRaw = headerProps[2]

  if tokenType ~= "JWT" then
    return nil
  end

  local tokenFields = core.tokenize(jwtRaw, " .")

  if #tokenFields ~= 3 then
    return nil
  end

  local jwtBody = tokenFields[2]
  local jwtHeader = tokenFields[1]
  local jwtSignature = tokenFields[3]

  local stringBody = txn.c:ub64dec(jwtBody)
  local stringHeader = txn.c:ub64dec(jwtHeader)
  local stringSignature = txn.c:ub64dec(jwtSignature)

  local json = newCjson()
  local decodedBody = json.decode(stringBody)
  local decodedHeader = json.decode(stringHeader)

  local jwtAlgo = decodedHeader['alg']

  return {
    algo = jwtAlgo,
    encodedBody = jwtBody,
    encodedHeader = jwtHeader,
    body = stringBody,
    decodedBody = decodedBody,
    signature = stringSignature,
  }
end

local function setReqParams(txn, valid, reason, jwtObj)
  txn.set_var(txn, 'txn.tkn.valid', valid)
  txn.set_var(txn, 'txn.tkn.reason', reason)

  txn.http:req_add_header('x-tkn-valid', valid)
  txn.http:req_add_header('x-tkn-reason', reason)

  if jwtObj ~= nil then
    txn.http:req_add_header('x-tkn-body', jwtObj.body)
    -- set additional information about token
    if jwtObj.decodedBody.st ~= nil then
      txn.http:req_add_header('x-tkn-stateless', 1)
      txn.set_var(txn, 'txn.tkn.stateless', 1)
    else
      txn.http:req_add_header('x-tkn-legacy', 1)
      txn.set_var(txn, 'txn.tkn.legacy', 1)
    end
    
    local json = newCjson()
    for key, value in pairs(jwtObj.decodedBody) do
      local encoded = tostring(value)

      if type(value) == 'table' then    
        encoded = json.encode(value)
      end

      txn:set_var("txn.tkn.payload." .. key, encoded)
    end

  end
end

-- selects first available token server from specified backend
local function selectJwtBackend()
  for _, backend in pairs(core.backends) do
    if backend and backend.name:sub(1, #JWT_TOKEN_SERVER_BACKEND) == JWT_TOKEN_SERVER_BACKEND then
      for _, server in pairs(backend.servers) do
        local stats = server:get_stats()

        if stats['status'] == 'UP' then
          return server:get_addr()
        end
      end
    end
  end

  return nil
end

-- checks passed token using token server backend
local function checkRules(jwtObj)
  local httpclient = core.httpclient()
  local backend = selectJwtBackend()

  if backend == nil then
    return false, "E_BACKEND_UNAVAIL"
  end
  
  local url = "http://" .. backend
  local result = httpclient:post({ url = url, body = jwtObj.body })

  if result.status == 0 then
    return false, "E_BACKEND_UNAVAIL"
  end
  
  return result.body == "ok", result.body
end

-- action entry point
local function verifyJWT(txn)
  local jwtObj = extractJWTFromHeader(txn)

  if jwtObj == nil then
    setReqParams(txn, 0, 'E_TKN_INVALID') 
    return
  end

  local res = jwks.validateJWTSignature(jwtObj)

  if res ~= true then
    setReqParams(txn, 0, 'E_TKN_INVALID')
    return
  end

  if jwtObj.decodedBody.st == nil then
    setReqParams(txn, 0, 'E_TKN_LEGACY', jwtObj)
    return
  end

  local filterResult, reason
  local now = core.now().sec
  local cached = verifyCache[jwtObj.signature]
  
  if cached ~= nil and cached.exp > now then
    -- use cache
    filterResult, reason = cached.data[0], cached.data[1]
  else
    filterResult, reason = checkRules(jwtObj)
    -- cache result
    verifyCache[jwtObj.signature] = {
      data = {
        filterResult,
        reason,
      },
      exp = now + JWT_CACHE_TTL,
    }
  end
  
  if filterResult == false then
    setReqParams(txn, 0, reason, jwtObj)
    return
  end

  -- finally all checks passed
  setReqParams(txn, 1, 'ok', jwtObj)
end

core.register_action('verify-jwt', {'http-req'}, verifyJWT)

-- start pollers
core.register_task(jwks.loader)

-- initial load
core.register_init(jwks.loadKeys)
