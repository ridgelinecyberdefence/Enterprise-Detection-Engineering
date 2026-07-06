SELECT
    eventtime,
    eventname,
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    json_extract_scalar(requestparameters, '$.snapshotId') AS snapshot_id,
    json_extract_scalar(requestparameters, '$.imageId')    AS image_id,
    json_extract_scalar(requestparameters, '$.attributeType') AS attribute,
    requestparameters AS raw_request
FROM cloudtrail_logs
WHERE eventname IN ('ModifySnapshotAttribute', 'ModifyImageAttribute')
  AND ( requestparameters LIKE '%"group":"all"%'
        OR regexp_like(requestparameters, '"userId":"[0-9]{12}"') )
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
ORDER BY eventtime;
