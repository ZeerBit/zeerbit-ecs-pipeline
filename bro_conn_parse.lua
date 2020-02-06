require('parse_helpers')

function bro_conn_prefix_all(tag, timestamp, record)
  local prefix = "zeek_connection_"
  local prefixed_record = {}
  for k,v in pairs(record) do
    if k:match("^%a") then
      prefixed_record[prefix..k] = v
      record[k] = nil
    end
  end
  for k,v in pairs(prefixed_record) do
    record[k] = v
  end
  return 1, timestamp, record
end

function bro_conn_parse_direction(tag, timestamp, record)
  local local_orig = variable_to_boolean(record["zeek_connection_local_orig"])
  local local_resp = variable_to_boolean(record["zeek_connection_local_resp"])
    
  if local_orig == true and local_resp == true then
    record["network_direction"] = "internal"
    return 1, timestamp, record
  end
      
  if local_orig == false and local_resp == false then
    record["network_direction"] = "external"
    return 1, timestamp, record
  end
  
  if local_orig == true and local_resp == false then
    record["network_direction"] = "outbound"
    return 1, timestamp, record
  end

  if local_orig == false and local_resp == true then
    record["network_direction"] = "inbound"
    return 1, timestamp, record
  end

  record["network_direction"] = "unknown"
  return 1, timestamp, record
end

function bro_conn_parse_bytes(tag, timestamp, record)
  local bytes = 0
  if tonumber(record["zeek_connection_orig_ip_bytes"]) ~= nil then
    record["source_bytes"] = tonumber(record["zeek_connection_orig_ip_bytes"])
    bytes = bytes + record["source_bytes"]
  end
  if tonumber(record["zeek_connection_resp_ip_bytes"]) ~= nil then
    record["destination_bytes"] = tonumber(record["zeek_connection_resp_ip_bytes"])
    bytes = bytes + record["destination_bytes"]
  end
  if bytes > 0 then
    record["network_bytes"] = bytes
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end

function bro_conn_parse_packets(tag, timestamp, record)
  local packets = 0
  if tonumber(record["source_packets"]) ~= nil then
    packets = packets + tonumber(record["source_packets"])
  end
  if tonumber(record["destination_packets"]) ~= nil then
    packets = packets + tonumber(record["destination_packets"])
  end
  if packets > 0 then
    record["network_packets"] = packets
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

function bro_conn_parse_icmp(tag, timestamp, record)
  if record["network_transport"] == "icmp" then
    record["icmp_type"] = record["source_port"]
    record["icmp_code"] = record["destination_port"]
    record["source_port"] = nil
    record["destination_port"] = nil
    record["zeek_connection_conn_state"] = nil
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end
