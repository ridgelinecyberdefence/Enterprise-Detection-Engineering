SELECT
    useridentity.sessioncontext.sessionissuer.username AS role,
    COUNT(DISTINCT sourceipaddress)                     AS external_sources,
    COUNT(*)                                            AS external_sessions,
    array_distinct(array_agg(sourceipaddress))          AS sources,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE useridentity.type = 'AssumedRole'
  AND NOT regexp_like(sourceipaddress, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')
  AND sourceipaddress NOT LIKE '%.amazonaws.com'
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
GROUP BY useridentity.sessioncontext.sessionissuer.username
ORDER BY external_sessions DESC;
