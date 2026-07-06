SELECT
    useridentity.arn  AS principal,
    useridentity.type AS principal_type,
    sourceipaddress   AS source_ip,
    COUNT(*)          AS object_reads,
    COUNT(DISTINCT json_extract_scalar(requestparameters, '$.bucketName')) AS buckets,
    min(eventtime) AS first_read,
    max(eventtime) AS last_read
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname   = 'GetObject'
  AND eventtime  >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY useridentity.arn, useridentity.type, sourceipaddress
HAVING COUNT(*) >= 500
ORDER BY object_reads DESC;
