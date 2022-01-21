local cjson  = require "cjson.safe"
local consul = require "consul"

local config = require "verify-jwt.config"

require("verify-jwt.print_r")

local json = cjson.new()

local ruleTable = {}
local M = {}

local function parseRule(prefix, consulKey, decoded)
  local trimmed = string.sub(consulKey, #prefix + 1)
  local type = string.match(trimmed, "^(.)/.+")
  local key = "g"

  if type == "u" then
    key = string.match(trimmed, "^./(.+)/.+")
  end

  core.log(core.info, string.format("GOT RULE key: %s", key))

  return key, decoded
end

function M.loadRules()
  local stime = core.now()
  local scount = 0
  local ruleTempTable = {}
  local keyPrefix = config.consul.keyPrefix
  local consulAddr = config.consul.addr

  local c = consul:new({
    addr = consulAddr
  })

	core.log(core.info, string.format("Loading rules catalog from %s", consulAddr))

  local data, err = c:kvGet(keyPrefix .. "?recurse=true", true)

  if err ~= nil then
		core.log(core.err, string.format("Failed to retrieve rule listing: %s", err))
		return
	end

  for _, entry in ipairs(data) do
    if type(entry.Value) == "string" then
        entry.Value = json.decode(entry.Value)

        if entry.Value == nil then
          core.log(core.err, string.format("Failed to decode rule: %s", entry.Value))
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

  scount = #ruleTempTable
  ruleTable = ruleTempTable

  core.log(
    core.info,
		string.format(
      "Loaded %d rules from catalog",
		  #ruleTempTable + 1
    )
  )
end

-- rule update runner
function M.loader()
	while true do
		core.sleep(config.consul.syncInterval)
		M.loadRules()
	end
end

function M.getRules(userId)
  local globalRules = ruleTable['g'] or {}
  local userRules = ruleTable[userId] or {}

  return {
    table.unpack(globalRules),
    table.unpack(userRules)
  }
end

return M
