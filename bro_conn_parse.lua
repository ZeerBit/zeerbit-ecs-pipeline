function bro_conn_parse_direction(tag, timestamp, record)
  if record["local_orig"] == "T" and record["local_resp"] == "T" then
    record["network_direction"] = "local"
  else 
    if record["local_orig"] == "T" then
      record["network_direction"] = "outbound"
    else 
      if record["local_resp"] == "T" then
        record["network_direction"] = "inbound"
      else
        return 0, timestamp, record
      end
    end
  end
  return 1, timestamp, record
end