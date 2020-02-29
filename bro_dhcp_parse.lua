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

-- If zeek_dhcp_client_fqdn (DHCP Option 81) is empty, use host.hostname + "." + host.domain to populate the field
function bro_dhcp_populate_missing_host_name(tag, timestamp, record)
  if (record["host_name"] == nil or record["host_name"] == "-") then
    if (record["host_hostname"] ~= nil and record["host_hostname"] ~= "-") then
      record["host_name"] = record["host_hostname"]
      if (record["host_domain"] ~= nil and record["host_domain"] ~= "-") then
        record["host_name"] = record["host_name"].."."..record["host_domain"]
      end
      return 1, timestamp, record
    else
      return 0, timestamp, record
    end
  else
    return 0, timestamp, record
  end
end
