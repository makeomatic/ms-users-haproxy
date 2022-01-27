local cjson  = require "cjson.safe"
local consul = require "verify-jwt.mod-consul"
local base64 = require "base64"
local socket = require "socket"

local config = require "verify-jwt.config"

require("verify-jwt.print_r")

local json = cjson.new()
local tmove = table.move
local jsonDecode = json.decode

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
}

local function parseRule(prefix, consulKey, decoded)
  local trimmed = string.sub(consulKey, #prefix + 1)
  local type = string.match(trimmed, "^(.)/.+")
  local key = "g"

  if type == "u" then
    key = string.match(trimmed, "^./(.+)/.+")
  end

  return key, decoded
end

local function getConsulKeys(c, key, separator)
  local query = key .. "?separator=" .. (separator or "/").."&keys=1"
  local keys, err = c:kvKeys(query, true)
  
  if err ~= nil then
		core.log(core.err, string.format("Failed to retrieved keys listing[%s]: %s", query, err))
		return {}
	end

  return keys
end

local function extractData(memTable, data)
  local keyPrefix = config.consul.keyPrefix

  for _, row in ipairs(data) do
    local entry = row.KV
    local decoded = base64.decode(entry.Value)
    entry.Value = jsonDecode(decoded)
    
    if entry.ModifyIndex > memTable.maxIndex then
      memTable.maxIndex = entry.ModifyIndex
    end

    if entry.Value == nil then
      core.Alert(string.format("Failed to decode rule: %s", entry.Value))
      goto skip_to_next
    end

    local key, rule = parseRule(keyPrefix, entry.Key, entry.Value)

    if memTable.rules[key] == nil then
      memTable.rules[key] = {}
    end

    table.insert(memTable.rules[key], rule)
    
    memTable.count = memTable.count + 1

    if memTable.count % 5000 == 0 then
      core.yield()
    end

    ::skip_to_next::
  end

  return memTable
end

local function getConsulValues(c, prefixes, memTable)
  local result = memTable
  local queries = {}

  for i = 1, #prefixes, 1 do
    queries[#queries+1] = {
      KV = {
        verb="get-tree",
        key=prefixes[i]
      }
    }
  end

  local data, err = c:trx(queries, true)

  if err ~= nil then
    core.log(core.err, string.format("Failed to retrieve rule listing[%s]: %s", prefix, err))
    return nil
  end

  result = extractData(memTable, data.Results)

  return result
end

function slice(tbl, first, last, step)
  local sliced = {}

  for i = first or 1, last or #tbl, step or 1 do
    sliced[#sliced+1] = tbl[i]
  end

  return sliced
end

function M.loadRules()
  local scount = 0

  local keyPrefix = config.consul.keyPrefix
  local consulAddr = config.consul.addr

  local c = consul:new({
    addr = consulAddr
  })

  local stime = socket.gettime()

	core.Info(string.format("Loading rules catalog from %s", consulAddr))

  local store = getMemTable()
  local keys = getConsulKeys(c, keyPrefix)

  local step = 10
  
  for _, key in pairs(keys) do
    local users = getConsulKeys(c, key)
    for i = 1, #users, step do
      local keysToGet = slice(users, i, i + step - 1)
      store = getConsulValues(c, keysToGet, store)
    end
  end


  core.Info("Load took: " .. socket.gettime() - stime)
  core.Info("Indexes: current=" .. M.consulModifyIndexMax .. " received=".. store.maxIndex)

  -- update rule table only if we have some changes
  if store.maxIndex ~= M.consulModifyIndexMax then
    M.store = store
    M.consulModifyIndexMax = store.maxIndex

    core.Info(
      string.format(
        "Loaded %s rules from catalog",
        M.store.count
      )
    )
  end
end

-- rule update runner
function M.loader()
	while true do
		core.sleep(config.consul.syncInterval)
		M.loadRules()
	end
end

function M.getRules(userId)
  local cached = M.ruleCache[userId]
  
  if cached ~= nil and cached.ruleVersion == M.consulModifyIndexMax then
    return cached
  end

  local userRules = M.store.rules[userId] or {}

  local result = {
    data = userRules,
    ruleVersion = M.consulModifyIndexMax
  }

  M.ruleCache[userId] = result

  return result
end

return M
