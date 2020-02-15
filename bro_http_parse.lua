require('parse_helpers')

function get_file_extension(url)
  return url:match("^.+%.(.+)$")
end

function bro_http_prefix_all(tag, timestamp, record)
  return 1, timestamp, record_prefix_all(record, "zeek_http_")
end

function bro_http_parse_uri(tag, timestamp, record)
  local uri = {};
  if record["zeek_http_uri"] ~= nil and record["zeek_http_uri"] ~= "-" then
    uri = record.zeek_http_uri:split("?")
  end
  
  record["url_path"] = uri[1]
  record["url_query"] = uri[2]
  if record["url_scheme"] ~= nil and record["url_domain"] ~= nil and record["url_port"] ~= nil then
    record["url_full"] = record["url_scheme"] .. "://" .. record["url_domain"] .. ":" .. record["url_port"]
    if record["url_path"] ~= nil then
      record["url_extension"] = get_file_extension(record["url_path"])
      record["url_full"] = record["url_full"] .. record["url_path"]
    else
      record["url_full"] = record["url_full"] .. "/"
    end
    if record["url_query"] ~= nil then
      record["url_full"] = record["url_full"] .. "?" .. record["url_query"]
    end
  end

  if record["url_full"] ~= nil then
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end

-- Only called when parsing tab log files, no need to account for getting original values as tables from json
function bro_http_parse_arrays(tag, timestamp, record)
  record["zeek_http_resp_fuids"]      = variable_to_table(record["zeek_http_resp_fuids"],",")
  record["zeek_http_resp_filenames"]  = variable_to_table(record["zeek_http_resp_filenames"],",")
  record["zeek_http_resp_mime_types"] = variable_to_table(record["zeek_http_resp_mime_types"],",")

  record["zeek_http_orig_fuids"]      = variable_to_table(record["zeek_http_orig_fuids"],",")
  record["zeek_http_orig_filenames"]  = variable_to_table(record["zeek_http_orig_filenames"],",")
  record["zeek_http_orig_mime_types"] = variable_to_table(record["zeek_http_orig_mime_types"],",")
  
  record["zeek_http_tags"]            = variable_to_table(record["zeek_http_tags"],",")
  
  -- To test 'proxied' parsing in the environment w/o a proxy, add this to $PREFIX/share/bro/site/local.bro
  -- redef HTTP::proxy_headers += { "ACCEPT-ENCODING", "ACCEPT-LANGUAGE" };
  record["zeek_http_proxied"]         = variable_to_table(record["zeek_http_proxied"],",")

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

-- Only calls when parsing JSON log format
function bro_http_cleanup_arrays(tag, timestamp, record)
  if type(record["zeek_http_tags"]) == 'table' and #record["zeek_http_tags"] == 0 then
    record["zeek_http_tags"] = nil
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end    
end
