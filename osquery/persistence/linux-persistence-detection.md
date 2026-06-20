# Linux Persistence Detection

osquery queries that detect common Linux persistence mechanisms: cron jobs, systemd services, shell profile modifications, SSH authorized keys, at jobs, and init scripts. Runs on any Linux endpoint with osquery installed — no agent-specific dependency.

## ATT&CK Coverage

- T1053.003 — Scheduled Task/Job: Cron
- T1543.002 — Create or Modify System Process: Systemd Service
- T1546.004 — Event Triggered Execution: Unix Shell Configuration Modification
- T1098.004 — Account Manipulation: SSH Authorized Keys

## Queries

### Cron Jobs — All Users

```sql
-- All crontab entries across the system
SELECT c.event,
       c.minute || ' ' || c.hour || ' ' || c.day_of_month || ' ' ||
       c.month || ' ' || c.day_of_week AS schedule,
       c.command,
       c.path
FROM crontab c
WHERE c.command != ''
ORDER BY c.path;
```

### Unexpected Systemd Services

```sql
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
```

### SSH Authorized Keys — All Users

```sql
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
```

### Shell Profile Modifications

```sql
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
```

### At Jobs

```sql
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
```

### Suspicious LD_PRELOAD Persistence

```sql
-- LD_PRELOAD configured at system level (library injection persistence)
SELECT path,
       size,
       mtime,
       datetime(mtime, 'unixepoch') AS modified_time
FROM file
WHERE path = '/etc/ld.so.preload'
  AND size > 0;
```

### Init Scripts (SysV)

```sql
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
```

## Deployment

```ini
# osquery.conf — add to schedule
{
  "schedule": {
    "linux_persistence_cron": {
      "query": "SELECT c.event, c.command, c.path FROM crontab c WHERE c.command != '';",
      "interval": 3600,
      "description": "Enumerate cron entries"
    },
    "linux_persistence_systemd": {
      "query": "SELECT name, source, status FROM systemd_units WHERE source NOT LIKE '/usr/lib/systemd/%' AND source NOT LIKE '/lib/systemd/%' AND sub_status = 'running';",
      "interval": 3600,
      "description": "Non-vendor systemd services"
    },
    "linux_persistence_ssh_keys": {
      "query": "SELECT ak.uid, u.username, ak.algorithm, ak.comment FROM authorized_keys ak JOIN users u ON ak.uid = u.uid;",
      "interval": 3600,
      "description": "SSH authorized keys"
    }
  }
}
```

## Learn More

- [Linux IR — Persistence Analysis](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/) — Linux persistence mechanism forensics
- [Incident Response — Linux Evidence Collection](https://ridgelinecyber.com/training/courses/practical-ir/) — volatile and persistent evidence on Linux
