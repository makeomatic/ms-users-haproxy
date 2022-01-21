local cjson = require "cjson.safe";

local strlower = string.lower;
local strfind = string.find;
local strmatch = string.match;

local jsonDecode = cjson.new().decode;

local function catch(what)
  return what[1]
end

local function try(what)
  local status, result = pcall(what[1]);
  if not status then
    return what[2](result);
  end

  return result;
end

local function isempty(s)
  return s == nil or s == '' or s == false;
end

local function isnumber(a)
  return try {
    function()
      local num = tonumber(a);
      return num ~= nil and num or tonumber(jsonDecode(a));
    end,

    catch {
      function()
        return nil;
      end
    }
  }
end

local function gte(value, filter)
  if isempty(value) then
    return false;
  end

  return isnumber(value) >= filter;
end

local function lte(value, filter)
  if isempty(value) then
    return false;
  end

  return isnumber(value) <= filter;
end

local function gt(value, filter)
  if isempty(value) then
    return false;
  end

  return isnumber(value) > filter;
end

local function lt(value, filter)
  if isempty(value) then
    return false;
  end

  return isnumber(value) < filter;
end

local function filterString(value, filter)
  if isempty(value) then
    return false;
  end

  return strfind(strlower(value), strlower(filter)) ~= nil;
end

local function startsWith(value, filter)
  if isempty(value) then
    return false;
  end

  return strmatch(strlower(value), strlower("^" .. filter)) ~= nil
end

local function eq(value, filter)
  return value == filter;
end

local opTypes = {
  gte = gte,
  lte = lte,
  gt = gt,
  lt = lt,
  match = filterString,
  eq = eq,
  sw = startsWith,
};

local function filter(op, opFilter, fieldValue)
  local thunk = opTypes[op];
  if type(thunk) ~= "function" then
    return error("not supported op: " .. op);
  end

  return thunk(fieldValue, opFilter);
end

local function matchFilter(valueToFilter, filterValue)
  local isOr = filterValue._or

  for op, opFilter in pairs(filterValue) do
    -- we should skip _or field
    if op ~= '_or' then
      -- dedup?
      local result = filter(op, opFilter, valueToFilter)
      if isOr and result then
        return true;
      elseif not isOr and not result then
        return false
      end
    end
  end

  return not isOr;
end

local filterType = {
  table = matchFilter,
  string = eq,
  number = eq,
  boolean = eq,
};

local function matchRule(data, filter)
  local isOr = filter._or

  for field, ops in pairs(filter) do
    -- we should skip _or field
    if field ~= '_or' then
      local result = filterType[type(ops)](data[field], ops)
      if isOr and result == true then
        return true
      elseif not isOr and result == false then
        return false
      end
    end
  end

  return not isOr
end

local function findMatches(data, filters)
  for _, filter in pairs(filters) do
      if matchRule(data, filter) == true then
        return true
      end
  end

  return false
end

return {
  findMatches = findMatches
}
