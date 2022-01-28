local cjson  = require "cjson.safe"
local base64 = require "base64"
local socket = require "socket"

local config = require "verify-jwt.config"

require("verify-jwt.print_r")

local json = cjson.new()

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
  store = getMemTable(),
}

local function parseRule(prefix, decoded)
  
  local type = string.match(prefix, "^(.)/.+")
  local key = "g"

  if type == "u" then
    key = string.match(prefix, "^./(.+)/.+")
  end

  return key, decoded
end


function M.loadRules()
  local path = "/rules/revocation-rules.conf"
  local file, err = io.open(path, "r")

  if err ~= nil then
    core.Alert("Unable to load keys from file: " .. path)
    return
  end

  local count = 0
  local stime = socket.gettime()

  for line in io.lines(path) do 
    local split = core.tokenize(line, "!")
    local ruleBody = string.sub(line, #split[1] + 2)
    local decoded = jsonDecode(ruleBody)
    local key, rule = parseRule(split[1], decoded)

    if M.store.rules[key] == nil then
      M.store.rules[key] = {}
    end

    table.insert(M.store.rules[key], rule)
    -- M.store.rules[key][#(M.store.rules[key])] = rule

    count = count + 1
  end

  file:close()

  core.Info("Loaded "..count.." rules, Load took: " .. socket.gettime() - stime)
  -- print_r({
  --   store = M.store.rules
  -- })
end

function M.getRules(userId)
  -- core.Info("Get user rules: " .. userId)
  local rules = M.store.rules[userId] or {}
  return rules
end

return M
