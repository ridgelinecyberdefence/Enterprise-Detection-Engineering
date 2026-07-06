-- All crontab entries across the system
SELECT c.event,
       c.minute || ' ' || c.hour || ' ' || c.day_of_month || ' ' ||
       c.month || ' ' || c.day_of_week AS schedule,
       c.command,
       c.path
FROM crontab c
WHERE c.command != ''
ORDER BY c.path;

-- Non-vendor systemd services (potential persistence)
SELECT name,
       source,
       status,
       sub_status,
       pid,
       description
FROM systemd_units
WHERE source NOT LIKE '/usr/lib/systemd/%'
  AND source NOT LIKE '/lib/systemd/%'
  AND sub_status = 'running'
ORDER BY name;

-- All SSH authorized keys that grant access to the system
SELECT ak.uid,
       u.username,
       ak.algorithm,
       ak.key,
       ak.comment,
       ak.options
FROM authorized_keys ak
JOIN users u ON ak.uid = u.uid
ORDER BY u.username;

-- Recently modified shell profiles (persistence via .bashrc, .profile, etc.)
SELECT path,
       filename,
       size,
       mtime,
       datetime(mtime, 'unixepoch') AS modified_time
FROM file
WHERE (
    path LIKE '/home/%/.bashrc'
    OR path LIKE '/home/%/.bash_profile'
    OR path LIKE '/home/%/.profile'
    OR path LIKE '/home/%/.zshrc'
    OR path LIKE '/root/.bashrc'
    OR path LIKE '/root/.bash_profile'
    OR path = '/etc/profile'
    OR path LIKE '/etc/profile.d/%'
    OR path = '/etc/bash.bashrc'
    OR path = '/etc/environment'
)
AND mtime > (strftime('%s', 'now') - 604800)  -- modified in last 7 days
ORDER BY mtime DESC;

-- Scheduled at jobs
SELECT path,
       filename,
       size,
       mtime,
       datetime(mtime, 'unixepoch') AS modified_time
FROM file
WHERE path LIKE '/var/spool/at/%'
  OR path LIKE '/var/spool/cron/atjobs/%'
ORDER BY mtime DESC;

-- LD_PRELOAD configured at system level (library injection persistence)
SELECT path,
       size,
       mtime,
       datetime(mtime, 'unixepoch') AS modified_time
FROM file
WHERE path = '/etc/ld.so.preload'
  AND size > 0;

-- SysV init scripts that may indicate persistence
SELECT path,
       filename,
       size,
       mtime,
       datetime(mtime, 'unixepoch') AS modified_time
FROM file
WHERE path LIKE '/etc/init.d/%'
  AND mtime > (strftime('%s', 'now') - 2592000)  -- modified in last 30 days
ORDER BY mtime DESC;
