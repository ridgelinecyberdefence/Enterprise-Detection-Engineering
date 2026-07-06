SELECT
    sourceipaddress AS source_ip,
    COUNT(*)        AS assume_calls,
    COUNT(DISTINCT json_extract_scalar(requestparameters, '$.roleArn')) AS distinct_roles,
    COUNT_IF(errorcode = 'AccessDenied') AS denied,
    array_distinct(array_agg(eventname)) AS verbs,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE eventname IN ('AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity')
  AND eventtime >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY sourceipaddress
HAVING COUNT(DISTINCT json_extract_scalar(requestparameters, '$.roleArn')) >= 5
ORDER BY distinct_roles DESC;
