local cjson = require "cjson.safe"
local openssl = {
  pkey = require 'openssl.pkey',
  digest = require 'openssl.digest',
  x509 = require 'openssl.x509',
  hmac = require 'openssl.hmac'
}

local base64 = require "verify-jwt.base64"
local http = require "verify-jwt.http-util"
local config = require"verify-jwt.config"

local json = cjson.new()

local M = {
  keys = {},
  config = {
    file = config.jwt.jwksFile,
    url = config.jwt.jwksUrl,
    timeout = 1000,
  }
}

local function parseJSON(raw)
  local res, err = json.decode(raw)
  if err ~= nil then
    core.Alert("Unable to parse JSON: " .. err)
  end

  return res
end

-- Read keys from JSON encoded jwks file
function M.readKeyFile(path)
  local file, err = io.open(path, "r")

  if err ~= nil then
    core.Alert("Unable to load keys from file: " .. path)
  end

  local content = file:read("*a")
  file:close()
  return content
end

-- Load keys from JSON encoded jwks url
function M.readUrlFile(url)
  local data, err = http.query('GET', url)
  if err ~= nil then
    core.Alert("Unable to load keys from url(" .. url .."):" .. err)
  end

  return data
end

-- Load keys using provided config
function M.loadKeys()
  local parsedKeys = {}

  if M.config.file ~= nil then
    core.Info("Load keys from file: " .. M.config.file)

    local raw = M.readKeyFile(M.config.file)
    local parsed = parseJSON(raw) or {}
    parsedKeys = parsed
  end

  if M.config.url ~= nil then
    local raw = M.readUrlFile(M.config.url)
    local parsed = parseJSON(raw) or {}
    parsedKeys = { table.unpack(parsedKeys), table.unpack(parsed)}
  end

  if #parsedKeys == 0 then
    core.Alert("No JWT keys loaded!")
    return
  end

  M.keys = {}

  for _, v in ipairs(parsedKeys) do
    local pkey = nil

    if v.cert ~= nil then
      pkey = openssl.pkey.new(v.cert)
    elseif v.secret ~= nil then
      pkey = v.secret
    else
      goto continueLabel
    end

    table.insert(M.keys, pkey)

    core.Info("JWT Key Cached: #id " .. v.kid)

    ::continueLabel::
  end
end

local function rsSignatureIsValid(tokenObj, publicKey)
  local algo = string.gsub(tokenObj.algo, "[REH]S", "SHA")
  local digest = openssl.digest.new(algo)
  
  digest:update(tokenObj.encodedHeader .. '.' .. tokenObj.encodedBody)
  
  return publicKey:verify(tokenObj.signature, digest)
end

local function hsSignatureIsValid(tokenObj, secret)
  local hmac = openssl.hmac.new(secret, string.gsub(tokenObj.algo, "[REH]S", "SHA"))
  local checksum = hmac:final(tokenObj.encodedHeader .. '.' .. tokenObj.encodedBody)
  return checksum == tokenObj.signature
end

local vFn = {
  string = hsSignatureIsValid,
  userdata = rsSignatureIsValid
}

function M.validateJWTSignature(tokenObj)
  local signatureValid = false

  for _, key in pairs(M.keys) do
    local fn = vFn[type(key)]
    
    local st, result = pcall(fn, tokenObj, key)
  
    if st == true then
      signatureValid = signatureValid or result
    end
  end

  return signatureValid
end

-- keys update runner
function M.loader()
	while true do
    core.Info("Load keys, sleep " .. config.jwt.syncInterval)
		core.sleep(config.jwt.syncInterval)
		M.loadKeys()
	end
end

return M
