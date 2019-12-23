-- Duplication of the split function definition
-- TODO include from parse_helpers.lua
function string:split (sep)
    local sep, fields = sep or ":", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

function bro_http_parse_arrays(tag, timestamp, record)
  if record["resp_fuids"] ~= nil and record["resp_fuids"] ~= "-" then
    record["zeek_http_resp_fuids"] = record.resp_fuids:split(",")
  end
  if record["resp_filenames"] ~= nil and record["resp_filenames"] ~= "-" then
    record["zeek_http_resp_filenames"] = record.resp_filenames:split(",")
  end
  if record["resp_mime_types"] ~= nil and record["resp_mime_types"] ~= "-" then
    record["zeek_http_resp_mime_types"] = record.resp_mime_types:split(",")
  end

  if record["zeek_http_resp_fuids"] ~= nil or record["zeek_http_resp_filenames"] ~= nil or record["zeek_http_resp_mime_types"] ~= nil then
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end

