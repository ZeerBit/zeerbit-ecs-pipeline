function string:split (sep)
    local sep, fields = sep or ":", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
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
  local flags_vector = "["
  for i,v in ipairs(flags) do
    if string.len(flags_vector) > 1 then
      flags_vector = flags_vector..","
    end
    flags_vector = flags_vector.."'"..v.."'"
  end
  flags_vector = flags_vector.."]"
  record["dns_header_flags"] = flags_vector
  return 1, timestamp, record
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
  return 1, timestamp, record
end