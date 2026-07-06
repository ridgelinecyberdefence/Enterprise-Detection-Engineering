SELECT
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
    COUNT(*)         AS deletes,
    min(eventtime)   AS first_delete,
    max(eventtime)   AS last_delete
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname  IN ('DeleteObject', 'DeleteObjects')
  AND eventtime  >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY useridentity.arn, sourceipaddress,
         json_extract_scalar(requestparameters, '$.bucketName')
HAVING COUNT(*) >= 100
ORDER BY deletes DESC;
