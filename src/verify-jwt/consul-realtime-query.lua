local cjson  = require "cjson.safe"
local consul = require "verify-jwt.mod-consul"
local base64 = require "base64"
local socket = require "socket"

local config = require "verify-jwt.config"

require("verify-jwt.print_r")

local json = cjson.new()
local tmove = table.move
local jsonDecode = json.decode
local base64 = base64.decode

local M = {
  ruleCache = {},
  getOps = {}
}

-- rule update runner
function M.loader()

end

function M.loadRules()
end

local consulAddr = config.consul.addr

local function extractData(data)
  local rules = {}
  local keyPrefix = config.consul.keyPrefix
  
  for _, entry in ipairs(data) do
    local decoded = base64(entry.Value)
    entry.Value = jsonDecode(decoded)
    
    if entry.Value == nil then
      core.Alert(string.format("Failed to decode rule: %s", entry.Value))
      goto skip_to_next
    end

    rules[#rules+1] = entry.Value
    
    ::skip_to_next::
  end

  return rules, maxIndex
end

local function wHttpClient(key)
  local url = "http://172.19.0.2:8500" .. "/v1/kv/" .. key .. "?recurse"

  local client = core.httpclient()
  core.Info("Query: " .. url)
  local response = client:get({ url = url })

  client = nil

  core.Info("Response: " .. response.status)

  if response.status == 404 then 
    return {}
  end

  return jsonDecode(response.body)
end

local function wTcpSocket(key)
  local addr = "172.19.0.2"
  local port = "8500"

  -- Set up a request to the service
  local hdrs = {
    [1] = string.format('host: %s:%s', addr, port),
    [2] = 'accept: */*',
    [3] = 'connection: close'
  }

  local url = "v1/kv/" .. key .. "?recurse"
  local req = {
    [1] = string.format('GET /%s HTTP/1.1', url),
    [2] = table.concat(hdrs, '\r\n'),
    [3] = '\r\n'
  }

  req = table.concat(req,  '\r\n')
  local res = {}

  local socket = core.tcp()
  
  socket:settimeout(1000)

  if socket:connect(addr, port) then
    if socket:send(req) then
      local headers = ''
      -- Skip response headers
      while true do
        local line, _ = socket:receive('*l')
        headers = headers .. (line or '')
        if not line then break end
        if line == '' then break end
      end
      
      local err = nil
      -- Get response body, if any
      local content, err = socket:receive('*a')

      if err ~= nil then
        core.Alert('XXX ' .. err .. "\n" .. headers)
      else 
        content = core.tokenize(content, "\r\b")
        res, err = jsonDecode(content[2])
        
        if err then
          core.Alert('Unable to parse json response for: ' .. url)
        end
      end
    else
        core.Alert('Could not connect to IP Checker server (send)')
    end

    socket:close()
  else
    core.Alert('Could not connect to consul (connect)')
  end

  return res
end

function M.fetchRulesConsul(userId)
  local keyPrefix = config.consul.keyPrefix
  -- local stime = socket.gettime()
  local key
  
  if userId == "g" then
    key = keyPrefix .. "g/"
  else
    key = keyPrefix .. "u/" .. userId .. "/"
  end

  local decoded = wTcpSocket(key)

  -- core.Info("Loaded " .. #decoded .. " rules")
  -- print_r(decoded)

  local rules = extractData(decoded)
  
  -- core.Info("Load took: " .. socket.gettime() - stime .. " got rules: " .. #rules .. " key: " .. key)

  return rules
end


function M.getRules(userId)
  local cached = M.ruleCache[userId]
  local now = core.now().sec
  
  if cached ~= nil and cached.ttl > now then
    return cached
  end
  
  local userRules = M.fetchRulesConsul(userId)
  local ttl = now + config.consul.syncInterval

  local result = {
    data = userRules,
    ttl = ttl
  }
  
  M.ruleCache[userId] = result

  return result
end

return M
