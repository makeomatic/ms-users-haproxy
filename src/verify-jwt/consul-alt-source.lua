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

local function getMemTable()
  return {
    rules = { g = {} },
    maxIndex = 0,
    count = 0,
  }
end

local M = {
  consulModifyIndexMax = 0,
  store = getMemTable(),
  ruleCache = {},
  invCache = {},
  getOps = {},
  lastInvTime = core.now().sec
}

local function extractData(data)
  local rules = {}
  local keyPrefix = config.consul.keyPrefix
  local maxIndex = 0

  for _, row in ipairs(data) do
    local entry = row.KV
    local decoded = base64(entry.Value)
    entry.Value = jsonDecode(decoded)
    
    if entry.ModifyIndex > maxIndex then
      maxIndex = entry.ModifyIndex
    end

    if entry.Value == nil then
      core.Alert(string.format("Failed to decode rule: %s", entry.Value))
      goto skip_to_next
    end

    rules[#rules+1] = entry.Value
    
    -- if #rules % 100 == 0 then
    --   core.yield()
    -- end

    ::skip_to_next::
  end

  return rules, maxIndex
end

local function getConsulValues(c, prefixes)
  local queries = {}

  for i = 1, #prefixes, 1 do
    queries[#queries+1] = {
      KV = {
        verb="get-tree",
        key=prefixes[i]
      }
    }
  end

  -- local stime = socket.gettime()
  local data, err = c:trx(queries, true)

  -- core.Info("TRX time: " .. socket.gettime() - stime)

  if err ~= nil then
    core.log(core.err, string.format("Failed to retrieve rule listing[%s]: %s", prefix, err))
    return nil
  end
  
  return extractData(data.Results)
end

local consulAddr = config.consul.addr

local c = consul:new({
  addr = consulAddr
})

function M.loadRules(userId)
  

  local keyPrefix = config.consul.keyPrefix
  
  -- local stime = socket.gettime()

  local key
  
  if userId == "g" then
    key = keyPrefix .. "g/"
  else
    key = keyPrefix .. "u/" .. userId .. "/"
  end

  local rules, maxIndex = getConsulValues(c, { key })

  -- core.Info("Load took: " .. socket.gettime() - stime .. " got rules: " .. #rules .. " key: " .. key)
  
  return rules, maxIndex
end

-- rule update runner
function M.loader()
	while true do
		core.sleep(2)
		M.destroyCaches()
	end
end

function M.destroyCaches()
  local now = core.now().sec
  -- print_r({ before = M.invCache })
  for t = now, M.lastInvTime, -1 do
    core.Info("Clean " .. t .. " entries: " .. #(M.invCache[t] or {}))
    for k, _ in pairs(M.invCache[t] or {}) do
      M.ruleCache[k] = nil
    end
    M.invCache[t] = nil
  end
  -- print_r({ after = M.invCache })
  M.lastInvTime = now
end

function M.getRules(userId)
  local cached = M.ruleCache[userId]
  local now = core.now().sec

  if cached ~= nil and cached.ttl > now then
    return cached
  end

  while M.getOps[userId] ~= nil  do
    core.msleep(1)
  end
  
  M.getOps[userId] = true

  local userRules, maxIndex = M.loadRules(userId)
  
  local ttl = now + config.consul.syncInterval

  local result = {
    data = userRules,
    ruleVersion = maxIndex,
    ttl = ttl
  }
  
  
  if M.invCache[ttl] == nil then
    M.invCache[ttl] = {}
  end
  
  local invCache = M.invCache[ttl]
  
  invCache[#invCache + 1] = userId

  M.ruleCache[userId] = result
  M.getOps[userId] = nil
  return result
end

return M
