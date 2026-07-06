SELECT
    awsregion        AS region,
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    COUNT(*)         AS calls,
    array_distinct(array_agg(eventname)) AS actions,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE awsregion NOT IN ('eu-west-2', 'eu-west-1')   -- replace with your operating regions
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
GROUP BY awsregion, useridentity.arn, sourceipaddress
ORDER BY calls DESC;
