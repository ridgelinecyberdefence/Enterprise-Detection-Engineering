SELECT
    useridentity.arn                     AS actor,
    sourceipaddress                      AS source_ip,
    COUNT(DISTINCT eventname)            AS distinct_create_verbs,
    COUNT(*)                             AS calls,
    array_distinct(array_agg(eventname)) AS actions,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE eventname IN ('CreateUser', 'CreateAccessKey', 'CreateLoginProfile',
                    'AttachUserPolicy', 'PutUserPolicy', 'CreatePolicyVersion')
  AND eventtime >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY useridentity.arn, sourceipaddress
HAVING COUNT(DISTINCT eventname) >= 2
ORDER BY distinct_create_verbs DESC;
