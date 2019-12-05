function bro_conn_parse_direction(tag, timestamp, record)
  if record["local_orig"] == "T" and record["local_resp"] == "T" then
    record["network_direction"] = "local"
  else 
    if record["local_orig"] == "T" then
      record["network_direction"] = "outbound"
    else 
      if record["local_resp"] == "T" then
        record["network_direction"] = "inbound"
      else
        return 0, timestamp, record
      end
    end
  end
  return 1, timestamp, record
end

function bro_conn_parse_bytes(tag, timestamp, record)
  local bytes = 0
  if tonumber(record["source_bytes"]) ~= nil then
    bytes = bytes + tonumber(record["source_bytes"])
  end
  if tonumber(record["destination_bytes"]) ~= nil then
    bytes = bytes + tonumber(record["destination_bytes"])
  end
  if bytes > 0 then
    record["network_bytes"] = bytes
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end
