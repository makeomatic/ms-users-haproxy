local cjson = require("cjson.safe")

require "verify-jwt.print_r"

local config = require "verify-jwt.config"

local JWT_CACHE_TTL = config.jwt.cacheTTL
local JWT_TOKEN_SERVER_BACKEND = config.jwt.tokenServer

local verifyCache = {}

local backendUnavailHeaders = {
  valid = 0,
  reason = "E_BACKEND_UNAVAIL"
}

local invalidTokenHeaders = {
  valid = 0,
  reason = "E_TKN_INVALID"
}

-- Extracts JWT token information using haproxy internal features
local function extractTokenFromHeader(txn)
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

  return jwtRaw
end

local function setReqHeaders(txn, headers)

  for key, value in pairs(headers) do
    local encoded = tostring(value)
    
    if type(value) == 'table' then    
      encoded = cjson.encode(value)
    end

    txn.set_var(txn, 'txn.tkn.'..key, encoded)
    txn.http:req_add_header('x-tkn-'..key, encoded)
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
local function checkToken(token)
  local httpclient = core.httpclient()
  local backend = selectJwtBackend()

  if backend == nil then
    return backendUnavailHeaders
  end
  
  local url = "http://" .. backend
  local result = httpclient:post({
    url = url,
    body = token,
  })
  
  local body = cjson.decode(result.body or "")

  if result.status == 0 or body == nil then
    return backendUnavailHeaders
  end

  return body
end

-- action entry point
local function verifyJWT(txn)
  local token = extractTokenFromHeader(txn)

  if token == nil then
    setReqHeaders(txn, invalidTokenHeaders) 
    return
  end

  local headers = {}
  local now = core.now().sec
  local cached = verifyCache[token]
  
  if cached ~= nil and cached.exp > now then
    -- use cache
    headers = cached.data
  else
    headers = checkToken(token)
    -- cache result
    verifyCache[token] = {
      data = headers,
      exp = now + JWT_CACHE_TTL,
    }
  end
  
  setReqHeaders(txn, headers)
end

core.register_action('verify-jwt', {'http-req'}, verifyJWT)
