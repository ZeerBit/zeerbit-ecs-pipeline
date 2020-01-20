function string:split (sep)
    local sep, fields = sep or ":", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

function variable_to_table(var, sep)
  if type(var) == 'string' then
    return var:split(sep)
  elseif type(var) == 'table' then
    return var
  else
    return nil
  end
end

function string:toboolean()
  --- constants
  local TRUE = {
      ['1'] = true,
      ['t'] = true,
      ['T'] = true,
      ['true'] = true,
      ['TRUE'] = true,
      ['True'] = true,
  }
  local FALSE = {
      ['0'] = false,
      ['f'] = false,
      ['F'] = false,
      ['false'] = false,
      ['FALSE'] = false,
      ['False'] = false,
  }
  
  if TRUE[self] == true then
      return true
  elseif FALSE[self] == false then
      return false
  else
      return nil
  end
end

function variable_to_boolean(var)
  if type(var) == 'string' then
    return var:toboolean()
  elseif type(var) == 'boolean' then
    return var
  else
    return nil
  end
end

