-- Hash critical binaries — compare against known-good baselines
SELECT path,
       filename,
       uid,
       gid,
       mode,
       size,
       mtime,
       datetime(mtime, 'unixepoch') AS modified,
       sha256
FROM hash
WHERE path IN (
    '/usr/bin/ssh', '/usr/bin/sudo', '/usr/bin/su',
    '/usr/bin/passwd', '/usr/bin/login', '/usr/bin/crontab',
    '/usr/bin/at', '/usr/sbin/sshd', '/usr/sbin/cron',
    '/usr/sbin/useradd', '/usr/sbin/usermod',
    '/usr/bin/curl', '/usr/bin/wget',
    '/bin/ls', '/bin/ps', '/bin/netstat', '/bin/ss',
    '/bin/bash', '/bin/sh', '/bin/cat', '/bin/grep',
    '/usr/bin/find', '/usr/bin/top', '/usr/bin/w', '/usr/bin/who',
    '/usr/bin/last', '/usr/bin/lsof'
);

-- Dotfiles in directories where they shouldn't exist
SELECT path,
       filename,
       uid,
       gid,
       size,
       mtime,
       datetime(mtime, 'unixepoch') AS modified
FROM file
WHERE (
    path LIKE '/tmp/.%'
    OR path LIKE '/dev/shm/.%'
    OR path LIKE '/var/tmp/.%'
    OR path LIKE '/usr/bin/.%'
    OR path LIKE '/usr/sbin/.%'
    OR path LIKE '/etc/.%'
    OR path LIKE '/opt/.%'
)
AND filename NOT IN ('.gitignore', '.gitkeep', '.placeholder')
AND type = 'regular'
ORDER BY mtime DESC;

-- All loaded kernel modules (compare to baseline for unauthorized additions)
SELECT name,
       size,
       used_by,
       status,
       address
FROM kernel_modules
WHERE status = 'Live'
ORDER BY name;

-- Processes visible in /proc but not in ps (rootkit hiding indicator)
-- Compare osquery process list with /proc entries
SELECT pid,
       name,
       path,
       cmdline,
       uid,
       state
FROM processes
WHERE pid NOT IN (
    SELECT CAST(filename AS INTEGER)
    FROM file
    WHERE path LIKE '/proc/%'
      AND filename GLOB '[0-9]*'
      AND type = 'directory'
)
AND pid > 1;

-- Libraries in non-standard paths (LD_PRELOAD rootkit indicator)
SELECT DISTINCT
    pe.pid,
    p.name AS process_name,
    pe.key,
    pe.value
FROM process_envs pe
JOIN processes p ON pe.pid = p.pid
WHERE pe.key = 'LD_PRELOAD'
  AND pe.value != '';

-- PAM modules (authentication backdoor indicator)
SELECT path,
       filename,
       size,
       sha256,
       mtime,
       datetime(mtime, 'unixepoch') AS modified
FROM hash
WHERE path LIKE '/lib/x86_64-linux-gnu/security/pam_%.so'
   OR path LIKE '/lib64/security/pam_%.so'
   OR path LIKE '/usr/lib/x86_64-linux-gnu/security/pam_%.so'
ORDER BY mtime DESC;

-- Monitor authentication database files
SELECT path,
       size,
       mtime,
       datetime(mtime, 'unixepoch') AS modified,
       sha256
FROM hash
WHERE path IN (
    '/etc/passwd',
    '/etc/shadow',
    '/etc/group',
    '/etc/gshadow',
    '/etc/sudoers'
);

-- /etc changes in the last 24 hours
SELECT path,
       filename,
       size,
       mtime,
       datetime(mtime, 'unixepoch') AS modified,
       uid,
       gid
FROM file
WHERE directory = '/etc'
  AND mtime > (strftime('%s', 'now') - 86400)
  AND type = 'regular'
ORDER BY mtime DESC;
