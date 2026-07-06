SELECT
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    awsregion        AS region,
    json_extract_scalar(requestparameters, '$.instanceType') AS instance_type,
    json_extract_scalar(requestparameters, '$.maxCount')     AS requested_count,
    json_extract_scalar(requestparameters, '$.imageId')      AS image_id,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen,
    COUNT(*)       AS launches
FROM cloudtrail_logs
WHERE eventname = 'RunInstances'
  AND NOT regexp_like(sourceipaddress, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
GROUP BY useridentity.arn, sourceipaddress, awsregion,
         json_extract_scalar(requestparameters, '$.instanceType'),
         json_extract_scalar(requestparameters, '$.maxCount'),
         json_extract_scalar(requestparameters, '$.imageId')
ORDER BY launches DESC;
