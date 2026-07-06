SELECT
    useridentity.arn  AS principal,
    useridentity.type AS principal_type,
    sourceipaddress   AS source_ip,
    COUNT(*)          AS enum_calls,
    array_distinct(array_agg(eventname)) AS actions,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('ListBuckets', 'ListObjects', 'ListObjectsV2',
                    'GetBucketAcl', 'GetBucketPolicy', 'GetBucketLocation')
  AND eventtime >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY useridentity.arn, useridentity.type, sourceipaddress
HAVING COUNT(*) >= 20
ORDER BY enum_calls DESC;
