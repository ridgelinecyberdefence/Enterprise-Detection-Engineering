SELECT
    eventtime,
    useridentity.arn AS principal,
    useridentity.type AS principal_type,
    sourceipaddress  AS source_ip,
    json_extract_scalar(additionaleventdata, '$.MFAUsed')        AS mfa_used,
    json_extract_scalar(responseelements, '$.ConsoleLogin')      AS result
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Success'
  AND json_extract_scalar(additionaleventdata, '$.MFAUsed') = 'No'
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
ORDER BY eventtime;
