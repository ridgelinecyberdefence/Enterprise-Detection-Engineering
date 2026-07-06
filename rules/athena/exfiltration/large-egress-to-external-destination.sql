SELECT
    srcaddr,
    dstaddr,
    dstport,
    COUNT(*)   AS flows,
    SUM(bytes) AS total_bytes
FROM vpc_flow_logs
WHERE action = 'ACCEPT'
  AND NOT regexp_like(dstaddr, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')
  AND "start" >= to_unixtime(current_timestamp - interval '1' hour)
GROUP BY srcaddr, dstaddr, dstport
HAVING SUM(bytes) >= 524288000
ORDER BY total_bytes DESC;
