local cjson = require "cjson.safe";

local strlower = string.lower;
local strfind = string.find;
local strmatch = string.match;

local jsonDecode = cjson.new().decode;

local tFunction = "function"
local orField = '_or'

local function isempty(s)
  return s == nil or s == '' or s == false;
end

local function isnumber(a)
  local num = tonumber(a);
  return num ~= nil and num;
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
  print_r({
    filter = filter, value = value,
    res = isnumber(value) < filter 
  })
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
  if type(thunk) ~= tFunction then
    return error("not supported op: " .. op);
  end

  return thunk(fieldValue, opFilter);
end

local function matchFilter(valueToFilter, filterValue)
  local isOr = filterValue._or
  local op
  local opFilter

  for op, opFilter in next, filterValue do
  -- for op, opFilter in pairs(filterValue) do
    -- we should skip _or field
    if op ~= orField then
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
  local field, ops

  for field, ops in next, filter do
    -- we should skip _or field
    if field ~= orField then
      local fn = filterType[type(ops)]
      local checkData = data[field]
      local result = fn(checkData, ops)

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
  for i = 1, #filters do
    local filter = filters[i]
    if matchRule(data, filter) then
      print_r({
        m = "Match on rule " .. i,
        data = data,
        filter = filter
      })
      return true
    end
  end

  return false
end

return {
  findMatches = findMatches
}
