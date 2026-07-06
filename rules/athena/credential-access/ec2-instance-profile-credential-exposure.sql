WITH role_sources AS (
    SELECT
        useridentity.sessioncontext.sessionissuer.username AS role,
        sourceipaddress AS source_ip,
        COUNT(*) AS calls,
        BOOL_OR(regexp_like(sourceipaddress, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')
                OR sourceipaddress LIKE '%.amazonaws.com') AS is_internal
    FROM cloudtrail_logs
    WHERE useridentity.type = 'AssumedRole'
      AND useridentity.sessioncontext.sessionissuer.username LIKE '%instance%'   -- adjust to your instance-role naming
      AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
    GROUP BY useridentity.sessioncontext.sessionissuer.username, sourceipaddress
)
SELECT role, source_ip, calls
FROM role_sources
WHERE is_internal = false
ORDER BY calls DESC;
