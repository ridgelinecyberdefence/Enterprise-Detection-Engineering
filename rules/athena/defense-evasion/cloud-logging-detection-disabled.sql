SELECT
    eventtime,
    eventname,
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    awsregion        AS region,
    errorcode        AS error
FROM cloudtrail_logs
WHERE eventname IN (
        'StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors',
        'DeleteDetector', 'UpdateDetector', 'DeleteMembers', 'DisassociateMembers',
        'StopConfigurationRecorder', 'DeleteConfigurationRecorder', 'DeleteFlowLogs')
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
ORDER BY eventtime;
