function string:split (sep)
    local sep, fields = sep or ":", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

function bro_dns_parse_answers(tag, timestamp, record)
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
end
