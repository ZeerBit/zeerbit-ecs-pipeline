require('parse_helpers')

function bro_ssl_prefix_all(tag, timestamp, record)
  return 1, timestamp, record_prefix_all(record, "zeek_ssl_")
end

-- Only called when parsing tab log files. JSON format has original values as booleans already
function bro_ssl_parse_booleans(tag, timestamp, record)
  record["tls_resumed"] = variable_to_boolean(record["zeek_ssl_resumed"])
  record["tls_established"] = variable_to_boolean(record["zeek_ssl_established"])

  if record["tls_resumed"] ~= nil or record["tls_established"] ~= nil then
    return 1, timestamp, record
  else 
    return 0, timestamp, record
  end
end

-- Only called when parsing tab log files. JSON format has original values as tables already
function bro_ssl_parse_fuids(tag, timestamp, record)
  local cert_chain_fuids, client_cert_chain_fuids
  if record["zeek_ssl_cert_chain_fuids"] ~= "(empty)" then
    cert_chain_fuids = record["zeek_ssl_cert_chain_fuids"]
  end
  if record["zeek_ssl_client_cert_chain_fuids"] ~= "(empty)" then
    client_cert_chain_fuids = record["zeek_ssl_client_cert_chain_fuids"]
  end
  
  record["zeek_ssl_cert_chain_fuids"] = variable_to_table(cert_chain_fuids, ",")
  record["zeek_ssl_client_cert_chain_fuids"] = variable_to_table(client_cert_chain_fuids, ",")
  
  if type(record["zeek_ssl_cert_chain_fuids"]) =='table' and #record["zeek_ssl_cert_chain_fuids"] == 0 then
    record["zeek_ssl_cert_chain_fuids"] = nil
  end
  
  if type(record["zeek_ssl_client_cert_chain_fuids"]) =='table' and #record["zeek_ssl_client_cert_chain_fuids"] ==0 then
    record["zeek_ssl_client_cert_chain_fuids"] = nil
  end

  return 1, timestamp, record
end

