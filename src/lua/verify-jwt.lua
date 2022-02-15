local cjson = require("cjson.safe")

require "verify-jwt.print_r"

local jwks = require "verify-jwt.jwks"
local config = require "verify-jwt.config"
local socket = require "socket"

local json = cjson.new()

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

  local decodedBody = json.decode(stringBody)
  local decodedHeader = json.decode(stringHeader)

  local jwtAlgo = decodedHeader['alg']

  return {
    raw = jwtRaw,
    algo = jwtAlgo,
    encodedBody = jwtBody,
    encodedHeader = jwtHeader,
    encodedSignature = jwtSignature,
    body = stringBody,
    header = stringHeader,
    parsedBody = decodedBody,
    parsedHeader = decodedHeader,
    signature = stringSignature,
  }
end

-- Validates JWT body and returns error message
local function validateJWTBody(jwtObj)
  local jwt = jwtObj.parsedBody
  local now = core.now().sec * 1000

  if (math.floor(jwt.exp) or now) < now then
    return false, 'expired'
  end

  return true
end

local function setReqParams(txn, valid, reason, token)
  txn.set_var(txn, 'txn.tkn.valid', valid)
  txn.http:req_add_header('x-tkn-valid', valid)

  txn.set_var(txn, 'txn.tkn.reason', reason)
  txn.http:req_add_header('x-tkn-reason', reason)

  for key, value in pairs(token) do
    local encoded = tostring(value)

    if type(value) == 'table' then
      encoded = json.encode(value)
    end

    txn:set_var("txn.tkn.payload." .. key, encoded)
    txn.http:req_add_header('x-tkn-payload-'.. key, encoded)
  end
end

local function selectJwtBackend()
  for _, backend in pairs(core.backends) do
    if backend and backend.name:sub(1, 10) == 'jwt-server' then
      for _, server in pairs(backend.servers) do
        local stats = server:get_stats()
        if stats['status'] == 'UP' then
          return server:get_addr()
        else
          core.Debug(backend.name .. " -> " .. server:get_addr() .. "- DOWN")
        end
      end
    end
  end

  return nil
end

local function checkRules(jwtObj)
  local httpclient = core.httpclient()
  local backend = selectJwtBackend()

  if backend == nil then
    return false, "no-backend"
  end

  local url = "http://" .. backend
  local result = httpclient:post({ url = url, body = jwtObj.body})

  if result.status == 0 then
    return false, "backend-unavail"
  end
  
  return result.body == "ok", result.body
end

local function verifyJWT(txn)
  local jwtObj = extractJWTFromHeader(txn)

  if jwtObj == nil then
    setReqParams(txn, 0, 'absent', {})
    return
  end

  local res = jwks.validateJWTSignature(jwtObj)

  if res ~= true then
    setReqParams(txn, 0, 'forged', {})
    return
  end

  local tokenBody = jwtObj.parsedBody

  -- local stime = socket.gettime()
  
  local filterResult, reason = checkRules(jwtObj)
  
  -- core.Info("Check time: " .. socket.gettime() - stime)

  if filterResult == false then
    setReqParams(txn, 0, reason, tokenBody)
    return
  end


  setReqParams(txn, 1, 'ok', tokenBody)
end

core.register_action('verify-jwt', {'http-req'}, verifyJWT)

-- start pollers
core.register_task(jwks.loader)

-- initial load
core.register_init(jwks.loadKeys)
