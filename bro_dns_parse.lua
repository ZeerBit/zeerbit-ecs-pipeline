function string:split (sep)
    local sep, fields = sep or ":", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

---checks if a string represents an ip address
-- @return true or false
-- https://luacode.wordpress.com/2012/01/09/checking-ip-address-format-in-lua/
function is_ip_address(ip)
 if not ip then return false end
 local a,b,c,d = ip:match("^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)$")
 a = tonumber(a)
 b = tonumber(b)
 c = tonumber(c)
 d = tonumber(d)
 if not a or not b or not c or not d then return false end
 if a<0 or 255<a then return false end
 if b<0 or 255<b then return false end
 if c<0 or 255<c then return false end
 if d<0 or 255<d then return false end
 return true
end

function bro_dns_determine_dns_type(tag, timestamp, record)
  if record["dns_response_code"] == nil or record["dns_response_code"] == "-" then
    record["dns_type"] = "query"
  else
    record["dns_type"] = "answer"
  end
  return 1, timestamp, record
end

function bro_dns_parse_answers(tag, timestamp, record)
  if record["answers"] ~= nil and record["TTLs"] ~= nil then
    local answers_data_table = record.answers:split(",")
    local answers_ttl_table = record.TTLs:split(",")

    local ordered_keys = {}

    for k in pairs(answers_data_table) do
        table.insert(ordered_keys, k)
    end

    table.sort(ordered_keys)
  
    local answers = {}
    local data_key = "data"
    local ttl_key = "ttl"
  
    for i = 1, #ordered_keys do
      local answer = {}
      if answers_data_table[i] ~= nil and answers_data_table[i] ~= "-" then
        answer[data_key] = answers_data_table[i]
        answer[ttl_key] = answers_ttl_table[i]
        answers[i] = answer
      end
    end
  
    if #answers > 0 then
      record["dns_answers"] = answers
      local resolved_ip = {}
      for k,v in pairs(answers_data_table) do
        if is_ip_address(v) then
          table.insert(resolved_ip,v)
        end
      end
      if #resolved_ip > 0 then
        record["dns_resolved_ip"] = resolved_ip
      end
    end
    
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end

function bro_dns_parse_flags(tag, timestamp, record)
  local flags = {}
  if record["AA"] == "T" then
    table.insert(flags, 'AA')
  end
  if record["TC"] == "T" then
    table.insert(flags, 'TC')
  end
  if record["RD"] == "T" then
    table.insert(flags, 'RD')
  end
  if record["RA"] == "T" then
    table.insert(flags, 'RA')
  end
  if #flags > 0 then
    record["dns_header_flags"] = flags
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end

function bro_dns_parse_zeek(tag, timestamp, record)
  if record["zeek"] == nil then
    record["zeek"] = {}
  end
  record["zeek"]["dns"] = {}
  if record["rejected"] == "T" then
    record["zeek"]["dns"]["rejected"] = true
  else
    record["zeek"]["dns"]["rejected"] = false
  end
  
  if record["answers"] ~= nil and record["answers"] ~= "-" then
    record["zeek"]["dns"]["answers"] = record.answers:split(",")
  end
  
  if record["TTLs"] ~= nil and record["TTLs"] ~= "-" then
    local ttls_strings_table = record.TTLs:split(",")
    local ttls_numbers_table = {}
    for k,v in pairs(ttls_strings_table) do
      table.insert(ttls_numbers_table, tonumber(v))
    end
    record["zeek"]["dns"]["ttls"] = ttls_numbers_table
  end
  
  return 1, timestamp, record
end