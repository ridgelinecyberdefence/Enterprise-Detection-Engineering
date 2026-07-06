SELECT
    sourceipaddress AS source_ip,
    COUNT_IF(json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Failure') AS failures,
    COUNT_IF(json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Success') AS successes,
    array_distinct(array_agg(useridentity.arn)) AS principals,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND eventtime >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY sourceipaddress
HAVING COUNT_IF(json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Failure') >= 10
   AND COUNT_IF(json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Success') >= 1
ORDER BY failures DESC;
