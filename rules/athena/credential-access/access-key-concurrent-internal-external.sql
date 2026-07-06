SELECT
    useridentity.accesskeyid AS access_key,
    useridentity.arn         AS principal,
    COUNT_IF(regexp_like(sourceipaddress,
        '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'))     AS internal_calls,
    COUNT_IF(NOT regexp_like(sourceipaddress,
        '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'))     AS external_calls,
    array_distinct(filter(array_agg(sourceipaddress),
        ip -> NOT regexp_like(ip,'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'))) AS external_sources,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE useridentity.type = 'IAMUser'
  AND useridentity.accesskeyid LIKE 'AKIA%'
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
GROUP BY useridentity.accesskeyid, useridentity.arn
HAVING COUNT_IF(regexp_like(sourceipaddress, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')) > 0
   AND COUNT_IF(NOT regexp_like(sourceipaddress, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')) > 0
ORDER BY external_calls DESC;
