require('parse_helpers')

function zeek_stats_prefix_all(tag, timestamp, record)
  return 1, timestamp, record_prefix_all(record, "zeek_stats_")
end
