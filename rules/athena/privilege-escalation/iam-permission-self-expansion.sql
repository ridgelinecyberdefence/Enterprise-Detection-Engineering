SELECT
    eventtime,
    useridentity.arn AS actor,
    sourceipaddress  AS source_ip,
    eventname,
    json_extract_scalar(requestparameters, '$.policyArn')    AS policy_arn,
    json_extract_scalar(requestparameters, '$.userName')     AS target_user,
    json_extract_scalar(requestparameters, '$.setAsDefault') AS set_as_default
FROM cloudtrail_logs
WHERE eventname IN ('AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy',
                    'PutRolePolicy', 'CreatePolicyVersion', 'SetDefaultPolicyVersion')
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
ORDER BY eventtime;
