require('parse_helpers')

-- zeerbit-zeek-scripts/conn-add-geo
function zeek_conn_custom_parse_geo(tag, timestamp, record)
  -- adds the following fields for final nesting under source.geo and destination.geo
  -- source_geo.location.lon
  -- source_geo.location.lat
  -- source_geo.country_iso_code
  -- destination_geo.location.lon
  -- destination_geo.location.lat
  -- destination_geo.country_iso_code
  
  local source_geo_lon      = record["zeek_connection_orig_geo_lon"]
  local source_geo_lat      = record["zeek_connection_orig_geo_lat"]
  local source_geo_cc       = record["zeek_connection_orig_geo_cc"]
  local destination_geo_lon = record["zeek_connection_resp_geo_lon"]
  local destination_geo_lat = record["zeek_connection_resp_geo_lat"]
  local destination_geo_cc  = record["zeek_connection_resp_geo_cc"]
  
  local source_location = {}
  local destination_location = {}
  
  if source_geo_lon ~= nil and source_geo_lon ~= "-" and source_geo_lat ~= nil and source_geo_lat ~= "-" then
    source_location["lon"] = source_geo_lon
    source_location["lat"] = source_geo_lat
  end

  if destination_geo_lon ~= nil and destination_geo_lon ~= "-" and destination_geo_lat ~= nil and destination_geo_lat ~= "-" then
    destination_location["lon"] = destination_geo_lon
    destination_location["lat"] = destination_geo_lat
  end
  
  local modified = false
  if table_size(source_location) > 0 then
    record["source_geo"] = {}
    record["source_geo"]["location"]      = source_location
    modified = true
  end
  if table_size(destination_location) > 0 then
    record["destination_geo"] = {}
    record["destination_geo"]["location"] = destination_location
    modified = true
  end
  if type(source_geo_cc) == "string" and string.len(source_geo_cc) > 1 then
    record["source_geo"]["country_iso_code"] = source_geo_cc
    modified = true
  end
  if type(destination_geo_cc) == "string" and string.len(destination_geo_cc) > 1 then
    record["destination_geo"]["country_iso_code"] = destination_geo_cc
    modified = true
  end

  if modified then
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end
