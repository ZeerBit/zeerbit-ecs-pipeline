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

  if record["orig_fuids"] ~= nil and record["orig_fuids"] ~= "-" then
    record["zeek_http_orig_fuids"] = record.orig_fuids:split(",")
  end
  if record["orig_filenames"] ~= nil and record["orig_filenames"] ~= "-" then
    record["zeek_http_orig_filenames"] = record.orig_filenames:split(",")
  end
  if record["orig_mime_types"] ~= nil and record["orig_mime_types"] ~= "-" then
    record["zeek_http_orig_mime_types"] = record.orig_mime_types:split(",")
  end
  
  if record["tags"] ~= nil and record["tags"] ~= "(empty)" then
    record["zeek_http_tags"] = record.tags:split(",")
  end
  
  -- To test 'proxied' parsing in the environment w/o a proxy, add this to $PREFIX/share/bro/site/local.bro
  -- redef HTTP::proxy_headers += { "ACCEPT-ENCODING", "ACCEPT-LANGUAGE" };
  if record["proxied"] ~= nil and record["proxied"] ~= "-" then
    record["zeek_http_proxied"] = record.proxied:split(",")
  end
  
  
  

  if record["zeek_http_resp_fuids"] ~= nil or 
     record["zeek_http_resp_filenames"] ~= nil or 
     record["zeek_http_resp_mime_types"] ~= nil or
     record["zeek_http_orig_fuids"] ~= nil or 
     record["zeek_http_orig_filenames"] ~= nil or 
     record["zeek_http_orig_mime_types"] ~= nil or
     record["zeek_http_tags"] ~= nil or
     record["zeek_http_proxied"] ~= nil
     then
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end

