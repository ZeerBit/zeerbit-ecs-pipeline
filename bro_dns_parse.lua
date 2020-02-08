require('parse_helpers')

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

---checks if a string represents an ip address - IPv4 or IPv6
-- @return true or false
-- credits to Paul Kulchenko and chrisfish https://stackoverflow.com/questions/10975935/lua-function-check-if-ipv4-or-ipv6-or-string
function is_ip46_address(ip)
  if type(ip) ~= "string" then return false end

  -- check for format 1.11.111.111 for ipv4
  local chunks = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
  if #chunks == 4 then
    for _,v in pairs(chunks) do
      if tonumber(v) > 255 then return false end
    end
    return true
  end

  -- check for ipv6 format, should be 8 'chunks' of numbers/letters
  -- without leading/trailing chars
  -- or fewer than 8 chunks, but with only one `::` group
  local addr = ip:match("^([a-fA-F0-9:]+)$")
  if addr ~= nil and #addr > 1 then
    -- address part
    local nc, dc = 0, false      -- chunk count, double colon
    for chunk, colons in addr:gmatch("([^:]*)(:*)") do
      if nc > (dc and 7 or 8) then return false end    -- max allowed chunks
      if #chunk > 0 and tonumber(chunk, 16) > 65535 then
        return false
      end
      if #colons > 0 then
        -- max consecutive colons allowed: 2
        if #colons > 2 then return false end
        -- double colon shall appear only once
        if #colons == 2 and dc == true then return false end
        if #colons == 2 and dc == false then dc = true end
      end
      nc = nc + 1      
    end
    return true
  end

  return false
end

function bro_dns_prefix_all(tag, timestamp, record)
  return 1, timestamp, record_prefix_all(record, "zeek_dns_")
end

function bro_dns_determine_dns_type(tag, timestamp, record)
  if record["_dns_response_code"] == nil or record["_dns_response_code"] == "-" then
    record["_dns_type"] = "query"
  else
    record["_dns_type"] = "answer"
  end
  return 1, timestamp, record
end

function bro_dns_parse_answers(tag, timestamp, record)
  if record["zeek_dns_answers"] ~= nil and record["zeek_dns_TTLs"] ~= nil then
    local answers_data_table = variable_to_table(record.zeek_dns_answers, ",")
    local answers_ttl_table = variable_to_table(record.zeek_dns_TTLs, ",")

    local ordered_keys = {}

    for k in pairs(answers_data_table) do
        table.insert(ordered_keys, k)
    end

    table.sort(ordered_keys)
  
    local answers = {}
    local data_key = "data"
    local ttl_key = "ttl"
    local class_key = "class"
    local class_value = nil
    
    local question_class = record["_dns_question_class"]
    if question_class ~= nil and question_class ~= "-" then
      if question_class == "C_INTERNET" then
        class_value = "IN"
      else
        class_value = question_class
      end
    end
  
    for i = 1, #ordered_keys do
      local answer = {}
      if answers_data_table[i] ~= nil and answers_data_table[i] ~= "-" then
        answer[data_key] = answers_data_table[i]
        answer[ttl_key] = tonumber(answers_ttl_table[i])
        if class_value ~= nil then
          answer[class_key] = class_value
        end
        answers[i] = answer
      end
    end
  
    if #answers > 0 then
      record["_dns_answers"] = answers
      local resolved_ip = {}
      local resolved_name = {}
      for k,v in pairs(answers_data_table) do
        if is_ip46_address(v) then
          table.insert(resolved_ip,v)
        else
          table.insert(resolved_name,v)
        end
      end
      if #resolved_ip > 0 then
        record["_dns_resolved_ip"] = resolved_ip
      end
      if #resolved_name > 0 then
        record["_dns_resolved_name"] = resolved_name
      end
    end
    
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end

function bro_dns_parse_flags(tag, timestamp, record)
  local flags = {}
  if variable_to_boolean(record["zeek_dns_AA"]) then
    table.insert(flags, 'AA')
  end
  if variable_to_boolean(record["zeek_dns_TC"]) then
    table.insert(flags, 'TC')
  end
  if variable_to_boolean(record["zeek_dns_RD"]) then
    table.insert(flags, 'RD')
  end
  if variable_to_boolean(record["zeek_dns_RA"]) then
    table.insert(flags, 'RA')
  end
  if #flags > 0 then
    record["_dns_header_flags"] = flags
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end

function bro_dns_parse_zeek(tag, timestamp, record)
  record["zeek_dns_rejected"] = variable_to_boolean(record["zeek_dns_rejected"])
  
  local vector = record["zeek_dns_answers"]
  if  vector ~= nil and vector ~= "-" then
    record["zeek_dns_answers"] = variable_to_table(vector, ",")
  else 
    record["zeek_dns_answers"] = nil
  end
  
  local vector = record["zeek_dns_TTLs"]
  if vector ~= nil and vector ~= "-" then
    local ttls_strings_table = variable_to_table(vector, ",")
    local ttls_numbers_table = {}
    for k,v in pairs(ttls_strings_table) do
      table.insert(ttls_numbers_table, tonumber(v))
    end
    record["zeek_dns_TTLs"] = nil
    record["zeek_dns_ttls"] = ttls_numbers_table
  else 
    record["zeek_dns_TTLs"] = nil
  end
  
  return 1, timestamp, record
end