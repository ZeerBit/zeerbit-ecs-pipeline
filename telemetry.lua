function set_event_created(tag, timestamp, record)
  record["_event_created"] = os.date("!%Y-%m-%dT%H:%M:%S.000Z", os.time())
  return 1, timestamp, record
end