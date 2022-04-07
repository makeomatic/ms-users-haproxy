local cjson = require("cjson.safe").new()

local function headers(applet)
  local headers = {}
  for k, v in pairs(applet.headers) do
      if (v[1]) then  -- (non folded header with multiple values)
          headers[k] = {}
          for _, val in pairs(v) do
              table.insert(headers[k], val)
          end
      else
          headers[k] = v[0]
      end
  end

  local response = cjson.encode(headers)

  applet:set_status(200)
  applet:add_header("content-length", string.len(response))
  applet:add_header("content-type", "application/json")
  applet:start_response()
  applet:send(response)
end

core.register_service("header-tracer", "http", headers)
