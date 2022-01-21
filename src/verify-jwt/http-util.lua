local http = require "socket.http"
local ltn12  = require "ltn12"

local M = {}

function M.query(method, url)
    -- response body
  local output = {}

  -- build request
  local request = {
    url     = url,
    method  = method or "GET",
    sink    = ltn12.sink.table(output),
    headers = { accept = "application/json" },
  }

  http.TIMEOUT = M.config.timeout

  if input then
    if type(input) == "string" then
      request.source = ltn12.source.string(input)
      request.headers["content-length"] = input:len()
    else
      return nil, "Invalid non-string input"
    end
  end

  local response, status = http.request(request)

  if not response then
    return nil, "Failed to execute request."
  end

  if not status or status ~= 200 then
    return nil, "Failed to execute request:" .. status
  end

  if not output or not output[response] or #output[response] < 0 then
    return nil, "Failed to execute request."
  end

  local data, err = json.decode(output[response])

  if not data or err ~= nil then
    return nil, tostring(err)
  end

  return data, nil
end

return M
