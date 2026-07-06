SELECT
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    COUNT(DISTINCT eventname) AS distinct_reads,
    COUNT(*)         AS total_reads,
    array_distinct(array_agg(eventsource)) AS services,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE readonly = 'true'
  AND NOT regexp_like(sourceipaddress, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')
  AND sourceipaddress NOT LIKE '%.amazonaws.com'
  AND eventtime >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY useridentity.arn, sourceipaddress
HAVING COUNT(DISTINCT eventname) > 8
ORDER BY distinct_reads DESC;
