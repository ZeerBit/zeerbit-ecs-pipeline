require('parse_helpers')

function zeek_stats_prefix_all(tag, timestamp, record)
  return 1, timestamp, record_prefix_all(record, "zeek_stats_")
end

function zeek_stats_add_mem_bytes(tag, timestamp, record)
  -- Stats::Info[mem] Amount of memory currently in use in MB.
  local conversion_rate = 1024 * 1024
  local mem_bytes = 0
  if record["zeek_stats_mem"] ~= nil then
    mem_bytes = tonumber(record["zeek_stats_mem"]) * conversion_rate
  end
  if mem_bytes > 0 then
    record["zeek_stats_mem_bytes"] = mem_bytes
    return 1, timestamp, record
  else
    return 0, timestamp, record
  end
end
