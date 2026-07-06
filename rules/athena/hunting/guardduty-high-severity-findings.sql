SELECT
    type        AS finding_type,
    severity,
    accountid   AS account,
    region,
    json_extract_scalar(resource, '$.resourceType')              AS resource_type,
    json_extract_scalar(service, '$.action.actionType')          AS action_type,
    COUNT(*)    AS occurrences,
    min(from_iso8601_timestamp(json_extract_scalar(service, '$.eventFirstSeen'))) AS first_seen,
    max(from_iso8601_timestamp(json_extract_scalar(service, '$.eventLastSeen')))  AS last_seen
FROM guardduty_findings
WHERE severity >= 7
  AND from_iso8601_timestamp(updatedat) >= current_timestamp - interval '24' hour
GROUP BY type, severity, accountid, region,
         json_extract_scalar(resource, '$.resourceType'),
         json_extract_scalar(service, '$.action.actionType')
ORDER BY severity DESC, occurrences DESC;
