require('parse_helpers')

function bro_dhcp_parse_uids(tag, timestamp, record)
  if record["uids"] ~= nil and type(record["uids"]) == "string" and record["uids"] ~= "-" then
    record["zeek_dhcp_uids"] = record.uids:split(",")
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end

function bro_dhcp_parse_msg_types(tag, timestamp, record)
  if record["msg_types"] ~= nil and type(record["msg_types"]) == "string" and record["msg_types"] ~= "-" then
    record["zeek_dhcp_msg_types"] = record.msg_types:split(",")
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end