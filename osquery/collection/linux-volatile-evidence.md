# Linux Volatile Evidence Collection

osquery queries for collecting volatile evidence from a live Linux system before containment. Captures the same evidence as traditional bash-based collection scripts but in structured, queryable format: running processes, network connections, logged-in users, open files, loaded kernel modules, and mount points.

## ATT&CK Coverage

Supports investigation across all tactics by preserving volatile endpoint state.

## Queries

### Running Processes with Full Detail

```sql
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
```

### Network Connections (All States)

```sql
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
```

### Currently Logged-In Users

```sql
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
```

### Open Files by Process

```sql
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
```

### Loaded Kernel Modules

```sql
-- All loaded kernel modules (rootkit detection)
SELECT name,
       size,
       used_by,
       status,
       address
FROM kernel_modules
WHERE status = 'Live'
ORDER BY name;
```

### Mount Points and Filesystems

```sql
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
```

### Environment Variables for All Processes

```sql
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
```

### DNS Resolver Configuration

```sql
-- DNS configuration (detect DNS hijacking)
SELECT type,
       address,
       netmask,
       options
FROM dns_resolvers
ORDER BY type;
```

## Deployment

Run as an ad hoc query pack during incident response:

```bash
# Run all collection queries and save results
osqueryi --json "SELECT p.pid, p.name, p.path, p.cmdline, p.uid, p.start_time FROM processes p ORDER BY p.start_time DESC;" > /tmp/evidence/processes.json
osqueryi --json "SELECT * FROM process_open_sockets ps JOIN processes p ON ps.pid = p.pid WHERE ps.state = 'ESTABLISHED';" > /tmp/evidence/connections.json
osqueryi --json "SELECT * FROM crontab;" > /tmp/evidence/crontab.json
osqueryi --json "SELECT * FROM kernel_modules WHERE status = 'Live';" > /tmp/evidence/kernel_modules.json
```

## Learn More

- [Linux IR — Volatile Evidence](https://training.ridgelinecyber.com/courses/linux-ir/) — Linux volatile evidence collection and preservation
- [Incident Response — Evidence Collection](https://training.ridgelinecyber.com/courses/practical-incident-response/) — evidence collection order and methodology
