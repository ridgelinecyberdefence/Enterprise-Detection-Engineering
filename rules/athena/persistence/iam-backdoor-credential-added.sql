SELECT
    eventtime,
    useridentity.arn AS actor,
    sourceipaddress  AS source_ip,
    eventname,
    json_extract_scalar(requestparameters, '$.userName') AS target_user
FROM cloudtrail_logs
WHERE eventname IN ('CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile')
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
  AND ( json_extract_scalar(requestparameters, '$.userName') IS NULL
        OR json_extract_scalar(requestparameters, '$.userName') <> useridentity.username )
ORDER BY eventtime;
