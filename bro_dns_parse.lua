function string:split (sep)
    local sep, fields = sep or ":", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
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