require('parse_helpers')

function bro_dhcp_prefix_all(tag, timestamp, record)
  return 1, timestamp, record_prefix_all(record, "zeek_dhcp_")
end

function bro_dhcp_parse_uids(tag, timestamp, record)
  local vector = record["zeek_dhcp_uids"]
  if vector ~= nil and type(vector) == "string" and vector ~= "-" then
    record["zeek_dhcp_uids"] = vector:split(",")
    return 1, timestamp, record
  else
    record["zeek_dhcp_uids"] = nil
    return 1, timestamp, record
  end
end

function bro_dhcp_parse_msg_types(tag, timestamp, record)
  local vector = record["zeek_dhcp_msg_types"]
  if vector ~= nil and type(vector) == "string" and vector ~= "-" then
    record["zeek_dhcp_msg_types"] = vector:split(",")
    return 1, timestamp, record
  else
    record["zeek_dhcp_msg_types"] = nil
    return 1, timestamp, record
  end
end