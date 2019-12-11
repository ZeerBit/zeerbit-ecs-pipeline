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

function bro_conn_parse_state(tag, timestamp, record)
  local state_codes = {
    ["S0"] = "Connection attempt seen, no reply",
    ["S1"] = "Connection established, not terminated",
    ["SF"] = "Normal establishment and termination",
    ["REJ"] = "Connection attempt rejected",
    ["S2"] = "Connection established and close attempt by originator seen",
    ["S3"] = "Connection established and close attempt by responder seen",
    ["RSTO"] = "Connection established, originator aborted",
    ["RSTR"] = "Responder sent a RST",
    ["RSTOS0"] = "Originator sent a SYN followed by a RST",
    ["RSTRH"] = "Responder sent a SYN ACK followed by a RST",
    ["SH"] = "Originator sent a SYN followed by a FIN",
    ["SHR"] = "Responder sent a SYN ACK followed by a FIN",
    ["OTH"] = "No SYN seen"
  }
  if state_codes[record["zeek_connection_conn_state"]] ~= nil then
    record["zeek_connection_state_msg"] = state_codes[record["zeek_connection_conn_state"]]
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end
