-- Duplication of the split function definition
-- TODO include from parse_helpers.lua
function string:split (sep)
    local sep, fields = sep or ":", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

function bro_dhcp_parse_uids(tag, timestamp, record)
  if record["uids"] ~= nil and record["uids"] ~= "-" then
    record["zeek_dhcp_uids"] = record.uids:split(",")
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end

function bro_dhcp_parse_msg_types(tag, timestamp, record)
  if record["msg_types"] ~= nil and record["msg_types"] ~= "-" then
    record["zeek_dhcp_msg_types"] = record.msg_types:split(",")
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end