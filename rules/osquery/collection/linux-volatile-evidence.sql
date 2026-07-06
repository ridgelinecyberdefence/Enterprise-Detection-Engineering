-- Complete process inventory with hashes
SELECT p.pid,
       p.parent AS ppid,
       p.name,
       p.path,
       p.cmdline,
       p.uid,
       u.username,
       p.gid,
       p.euid,
       p.state,
       p.nice,
       p.start_time,
       datetime(p.start_time, 'unixepoch') AS started,
       p.resident_size / 1048576 AS memory_mb,
       h.sha256
FROM processes p
LEFT JOIN users u ON p.uid = u.uid
LEFT JOIN hash h ON p.path = h.path
WHERE p.pid > 1
ORDER BY p.start_time DESC;

-- All TCP/UDP connections with process attribution
SELECT ps.pid,
       p.name,
       p.path,
       ps.family,
       ps.protocol,
       ps.local_address,
       ps.local_port,
       ps.remote_address,
       ps.remote_port,
       ps.state
FROM process_open_sockets ps
JOIN processes p ON ps.pid = p.pid
WHERE ps.state != ''
ORDER BY ps.state, ps.remote_address;

-- Active login sessions
SELECT type,
       user,
       tty,
       host,
       time,
       datetime(time, 'unixepoch') AS login_time,
       pid
FROM last
WHERE time > (strftime('%s', 'now') - 86400)
  AND type = 7  -- USER_PROCESS (active login)
ORDER BY time DESC;

-- Open file handles (network sockets, regular files, pipes)
SELECT pof.pid,
       p.name,
       pof.fd,
       pof.path,
       pof.socket AS socket_info
FROM process_open_files pof
JOIN processes p ON pof.pid = p.pid
WHERE pof.path NOT LIKE '/proc/%'
  AND pof.path NOT LIKE '/dev/null'
  AND pof.path != ''
ORDER BY p.name, pof.fd;

-- All loaded kernel modules (rootkit detection)
SELECT name,
       size,
       used_by,
       status,
       address
FROM kernel_modules
WHERE status = 'Live'
ORDER BY name;

-- Mounted filesystems (detect attacker-mounted shares or tmpfs)
SELECT device,
       path,
       type,
       flags,
       blocks,
       blocks_available,
       blocks_size
FROM mounts
ORDER BY path;

-- LD_PRELOAD and suspicious environment variables
SELECT pe.pid,
       p.name,
       pe.key,
       pe.value
FROM process_envs pe
JOIN processes p ON pe.pid = p.pid
WHERE pe.key IN ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'HISTFILE',
                  'http_proxy', 'https_proxy', 'PROMPT_COMMAND')
ORDER BY pe.key;

-- DNS configuration (detect DNS hijacking)
SELECT type,
       address,
       netmask,
       options
FROM dns_resolvers
ORDER BY type;
