SELECT
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    COUNT(*)         AS reads,
    COUNT(DISTINCT json_extract_scalar(requestparameters, '$.secretId')) AS distinct_secrets,
    array_agg(DISTINCT json_extract_scalar(requestparameters, '$.secretId')) AS secrets,
    min(eventtime) AS first_read,
    max(eventtime) AS last_read
FROM cloudtrail_logs
WHERE eventsource = 'secretsmanager.amazonaws.com'
  AND eventname   = 'GetSecretValue'
  AND eventtime  >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY useridentity.arn, sourceipaddress
HAVING COUNT(DISTINCT json_extract_scalar(requestparameters, '$.secretId')) >= 5
ORDER BY distinct_secrets DESC;
