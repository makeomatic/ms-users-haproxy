local http   = require("socket.http")
local ltn12  = require("ltn12")
local cjson  = require("cjson.safe")
local base64 = require("base64")

require("verify-jwt.print_r")

local json = cjson.new()

-- module config
local _M = {
    version = "0.01",
    kv      = { api = "/v1/kv" },
    transaction = { api = "/v1/txn" }
}

-- Execute Consul API commands.
-- Executes calls against the Consul HTTP API and
-- handles the result(s) including JSON decoding.
-- @param self    Module object
-- @param api     The complete API call string
-- @param input   Optional input body to the API request
-- @param method  Optional HTTP method - defaults to GET
-- @return        Result and error or nil
local function callConsul (self, api, parse, input, method)
    -- add datacenter if specified
    if self.dc then api = api .. "?dc=" .. self.dc end

    -- response body
    local output = {}

    -- build request
    local request = {
        url     = self.url .. api,
        method  = method or "GET",
        sink    = ltn12.sink.table(output),
        headers = { accept = "application/json" },
    }

    -- set create option if specified
    if self.create then
        request.create = self.create
    end

    -- set timeout
    http.TIMEOUT = self.timeout

    -- add input if specified and valid
    if input then
        if type(input) == "string" then
            request.source = ltn12.source.string(input)
            request.headers["content-length"] = input:len()
        else
            -- error out - we only support strings
            return nil, "Invalid non-string input"
        end
    end

    -- execute request
    local response, status, headers = http.request(request)
    
    -- check return
    if not response then
        -- error out
        return nil, "Failed to execute request."
    end

    -- check status
    if not status or status ~= 200 then
        -- error out
        return nil, "Failed to execute request.  Consul returned: " .. status
    end

    -- validate output
    if not output or not output[response] or #output[response] < 0 then
        -- error out
        return nil, "Failed to execute request.  Consul returned empty response."
    end

    local data, err

    -- decode response output
    if parse then
      local decoder = cjson.new()
      data, err = decoder.decode(output[response])
    else 
      data = output[response]
    end

    -- check return
    if not data or err ~= nil then
      -- error out
      return nil, tostring(err)
    end

    -- all okay
    return data, nil
end

-- Create a module object.
-- Creates a module object from scratch or optionally
-- based on another passed object.  The following object
-- members are accepted:
-- dc        Optional datacenter attribute - default nil
-- addr      Optional Consul connection address - defaults to "127.0.0.1:8500"
--           from environment or 127.0.0.1:8500
-- url       Optional url override - defaults to http://<addr>
-- create    Optional http request.create function
-- timeout   Optional http request timeout - defaults to 15 seconds
-- @param o  Optional object settings
-- @return   Module object
function _M:new (o)
    local o   = o or {} -- create table if not passed
    o.dc      = o.dc or nil
    o.addr    = o.addr or "127.0.0.1:8500"
    o.url     = "http://" .. o.addr
    o.create  = o.create or nil
    o.timeout = o.timeout or 15
    -- set self
    setmetatable(o, self)
    self.__index = self
    -- return table
    return o
end

-- Get a key/value pair.
-- @param key     The key name to retrieve
-- @param parse   parse response body
-- @param decode  Optionally base64 decode values
-- @return        Result and error or nil
function _M:kvGet (key, parse, decode)
    -- build call
    local api = self.kv.api .. "/" .. key

    -- make request
    local data, err = callConsul(self, api, parse)

    -- attempt base64 decoding if asked
    if data and err == nil and decode then
        for _, entry in ipairs(data) do
            if type(entry.Value) == "string" then
                local decoded = base64.decode(entry.Value)
                if decoded then
                    entry.Value = decoded
                end
            end
        end
    end

    -- return result
    return data, err
end

-- List all keys under a prefix.
-- @param prefix  The k/v prefix to list
-- @return        Result and error or nil
function _M:kvKeys (prefix)
    -- build call
    local api = self.kv.api .. "/" .. prefix .. "?keys"

    -- make request
    return callConsul(self, api, true)
end

-- Write a key/value pair.
-- @param key     The key name to write
-- @param value   The string value to write
-- @return        Result and error or nil
function _M:kvPut (key, value)
    -- build call
    local api = self.kv.api .. "/" .. key

    -- make request
    return callConsul(self, api, value, "PUT")
end

-- Delete a key or prefix.
-- @param key      The key name or prefix to delete
-- @param recurse  Optionally delete all keys under the given prefix
-- @return         Result and error or nil
function _M:kvDelete (key, recurse)
    -- build call
    local api = self.kv.api .. "/" .. key
    if recurse then api = api .. "?recurse" end

    -- make request
    return callConsul(self, api, nil, "DELETE")
end

function _M:trx(ops, parse)
  local api = self.transaction.api
  return callConsul(self, api, parse, json.encode(ops), "PUT")
end

-- return module table
return _M