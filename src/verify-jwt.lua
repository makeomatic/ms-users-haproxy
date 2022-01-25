local cjson = require("cjson.safe")

require "verify-jwt.print_r"

local matcher = require "verify-jwt.match"
local consulSource = require "verify-jwt.consul-source"
local jwks = require "verify-jwt.jwks"
local config = require "verify-jwt.config"

local json = cjson.new()
local getRules = consulSource.getRules
local findMatches = matcher.findMatches

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

local tokenCheckCache = {}

local function dropCache()
  tokenCheckCache = {}
end

local function checkRules(jwtObj)
  local filterResult
  local tokenKey = jwtObj.encodedSignature
  local tokenBody = jwtObj.parsedBody 

  local cached = tokenCheckCache[tokenKey]
  local now = core.now().sec

  if cached ~= nil and cached.ttl > now then 
    filterResult = tokenCheckCache[tokenKey].data
  else
    local rules = getRules(tokenBody.username)
    filterResult = findMatches(tokenBody, rules)

    tokenCheckCache[tokenKey] = {
      ttl = now + config.jwt.cacheTTL,
      data = filterResult
    }

    return filterResult
  end
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

  local res, msg = validateJWTBody(jwtObj)
  if res == false then
    setReqParams(txn, 0, msg, tokenBody)
    return
  end

  local filterResult = checkRules(jwtObj)
  if filterResult == true then
    setReqParams(txn, 0, 'blacklisted', tokenBody)
    return
  end

  setReqParams(txn, 1, 'ok', tokenBody)
end

consulSource.onreload = dropCache

core.register_action('verify-jwt', {'http-req'}, verifyJWT)

-- start pollers
core.register_task(consulSource.loader)
core.register_task(jwks.loader)

-- initial load
core.register_init(consulSource.loadRules)
core.register_init(jwks.loadKeys)
