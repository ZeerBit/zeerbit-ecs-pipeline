require('parse_helpers')

function bro_ssl_parse_booleans(tag, timestamp, record)
  if record["resumed"] == "T" then
    record["tls_resumed"] = true
  else
    if record["resumed"] == "F" then
      record["tls_resumed"] = false
    end
  end

  if record["established"] == "T" then
    record["tls_established"] = true
  else 
    if record["established"] == "F" then
      record["tls_established"] = false
    end
  end
  
  if record["tls_resumed"] ~= nil or record["tls_established"] ~= nil then
    return 1, timestamp, record
  else 
    return 0, timestamp, record
  end
end

function bro_ssl_parse_fuids(tag, timestamp, record)
  if record["cert_chain_fuids"] ~= nil and record["cert_chain_fuids"] ~= "(empty)" then
    record["zeek_ssl_cert_chain_fuids"] = record.cert_chain_fuids:split(",")
  end
  if record["client_cert_chain_fuids"] ~= nil and record["client_cert_chain_fuids"] ~= "(empty)" then
    record["zeek_ssl_client_cert_chain_fuids"] = record.client_cert_chain_fuids:split(",")
  end

  if record["zeek_ssl_cert_chain_fuids"] ~= nil or record["zeek_ssl_client_cert_chain_fuids"] ~= nil then
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end

