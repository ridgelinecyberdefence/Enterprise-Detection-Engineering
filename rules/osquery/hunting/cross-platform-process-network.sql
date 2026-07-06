-- What's listening? Cross-platform network listener inventory
SELECT DISTINCT p.name,
       p.path,
       p.cmdline,
       p.uid,
       u.username,
       lp.port,
       lp.protocol,
       lp.address
FROM listening_ports lp
JOIN processes p ON lp.pid = p.pid
LEFT JOIN users u ON p.uid = u.uid
WHERE lp.port != 0
ORDER BY lp.port;

-- Which processes are talking to external IPs?
SELECT DISTINCT p.name,
       p.path,
       p.cmdline,
       p.uid,
       ps.remote_address,
       ps.remote_port,
       ps.local_port,
       ps.state
FROM process_open_sockets ps
JOIN processes p ON ps.pid = p.pid
WHERE ps.remote_address != ''
  AND ps.remote_address != '0.0.0.0'
  AND ps.remote_address != '127.0.0.1'
  AND ps.remote_address != '::1'
  AND ps.remote_address NOT LIKE '10.%'
  AND ps.remote_address NOT LIKE '172.16.%'
  AND ps.remote_address NOT LIKE '172.17.%'
  AND ps.remote_address NOT LIKE '172.18.%'
  AND ps.remote_address NOT LIKE '172.19.%'
  AND ps.remote_address NOT LIKE '172.2_.%'
  AND ps.remote_address NOT LIKE '172.3_.%'
  AND ps.remote_address NOT LIKE '192.168.%'
  AND ps.state = 'ESTABLISHED'
ORDER BY p.name;

-- Processes matching known attacker tool names
SELECT name,
       path,
       cmdline,
       uid,
       pid,
       parent AS ppid,
       start_time,
       datetime(start_time, 'unixepoch') AS started
FROM processes
WHERE name IN (
    'nc', 'ncat', 'netcat', 'socat',
    'python', 'python3', 'perl', 'ruby',
    'curl', 'wget',
    'nmap', 'masscan',
    'chisel', 'ligolo', 'gost',
    'mimikatz', 'rubeus',
    'rclone',
    'xmrig', 'minerd', 'cpuminer'
)
OR cmdline LIKE '%/dev/tcp/%'
OR cmdline LIKE '%-e /bin/sh%'
OR cmdline LIKE '%-e /bin/bash%'
OR cmdline LIKE '%reverse_tcp%'
ORDER BY start_time DESC;

-- Executables running from temp/staging locations
SELECT name,
       path,
       cmdline,
       uid,
       pid,
       start_time,
       datetime(start_time, 'unixepoch') AS started
FROM processes
WHERE (
    path LIKE '/tmp/%'
    OR path LIKE '/var/tmp/%'
    OR path LIKE '/dev/shm/%'
    OR path LIKE '%/Downloads/%'
    OR path LIKE '%/AppData/Local/Temp/%'
    OR path LIKE 'C:\Windows\Temp\%'
    OR path LIKE 'C:\Temp\%'
)
AND name NOT IN ('apt', 'dpkg', 'yum', 'pip', 'npm')
ORDER BY start_time DESC;

-- Processes spawned by web servers, databases, or interpreters
SELECT p.name AS child_name,
       p.path AS child_path,
       p.cmdline AS child_cmdline,
       p.pid AS child_pid,
       pp.name AS parent_name,
       pp.path AS parent_path,
       p.uid,
       u.username
FROM processes p
JOIN processes pp ON p.parent = pp.pid
LEFT JOIN users u ON p.uid = u.uid
WHERE pp.name IN (
    'apache2', 'httpd', 'nginx', 'tomcat',
    'java', 'node', 'php-fpm', 'uwsgi',
    'postgres', 'mysqld', 'mongod',
    'docker', 'containerd'
)
AND p.name IN (
    'sh', 'bash', 'dash', 'zsh',
    'python', 'python3', 'perl', 'ruby',
    'curl', 'wget', 'nc', 'ncat'
)
ORDER BY p.start_time DESC;

-- Processes consuming excessive CPU (potential cryptomining)
SELECT name,
       path,
       cmdline,
       uid,
       pid,
       CAST(cpu_time AS REAL) / 10000000 AS cpu_seconds,
       resident_size / 1048576 AS memory_mb,
       start_time,
       datetime(start_time, 'unixepoch') AS started
FROM processes
WHERE cpu_time > 36000000000  -- > 1 hour CPU time
ORDER BY cpu_time DESC
LIMIT 20;
