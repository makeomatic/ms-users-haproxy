local cjson  = require "cjson.safe"
local consul = require "consul"

local config = require "verify-jwt.config"

require("verify-jwt.print_r")

local json = cjson.new()
local tmove = table.move
local jsonDecode = json.decode

local M = {
  consulModifyIndexMax = 0,
  ruleTable = {},
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

function M.loadRules()
  local scount = 0
  local ruleTempTable = { g = {}}
  local keyPrefix = config.consul.keyPrefix
  local consulAddr = config.consul.addr

  local c = consul:new({
    addr = consulAddr
  })

	core.log(core.debug, string.format("Loading rules catalog from %s", consulAddr))

  local data, err = c:kvGet(keyPrefix .. "?recurse=true", true)

  if err ~= nil then
		core.log(core.err, string.format("Failed to retrieve rule listing: %s", err))
		return
	end

  local maxIndex = 0

  for _, entry in ipairs(data) do
    if type(entry.Value) == "string" then
        entry.Value = jsonDecode(entry.Value)
        
        if entry.ModifyIndex > maxIndex then
          maxIndex = entry.ModifyIndex
        end

        if entry.Value == nil then
          core.Alert(string.format("Failed to decode rule: %s", entry.Value))
          goto skip_to_next
        end

        local key, rule = parseRule(keyPrefix, entry.Key, entry.Value)

        if ruleTempTable[key] == nil then
          ruleTempTable[key] = {}
        end

        table.insert(ruleTempTable[key], rule)

        ::skip_to_next::
    end
  end

  core.Debug("Indexes: current=" .. M.consulModifyIndexMax .. " received="..maxIndex)
  -- update rule table only if we have some changes
  if maxIndex ~= M.consulModifyIndexMax then
    M.ruleTable = ruleTempTable
    M.consulModifyIndexMax = maxIndex

    core.Info(
      string.format(
        "Loaded %s rules from catalog",
        #data
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

  -- generate new table
  local globalRules = M.ruleTable.g or {}
  local userRules = M.ruleTable[userId] or {}

  local all = {}

  tmove(globalRules, 1, #globalRules, 1, all)
  tmove(userRules, 1, #userRules, #all+1, all)

  local result = {
    data = all,
    ruleVersion = M.consulModifyIndexMax
  }

  M.ruleCache[userId] = result
  
  return result
end

return M
