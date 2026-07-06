SELECT
    eventtime,
    eventname,
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    json_extract_scalar(requestparameters, '$.keyId')               AS key_id,
    json_extract_scalar(requestparameters, '$.pendingWindowInDays') AS pending_days
FROM cloudtrail_logs
WHERE eventsource = 'kms.amazonaws.com'
  AND eventname IN ('ScheduleKeyDeletion', 'DisableKey', 'DisableKeyRotation', 'PutKeyPolicy')
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
ORDER BY eventtime;
