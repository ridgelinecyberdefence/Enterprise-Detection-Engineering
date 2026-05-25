# Cross-Platform Asset Discovery

osquery queries for asset inventory and discovery across Linux, macOS, and Windows: installed packages, user accounts, group memberships, listening services, and system configuration. Provides the baseline that makes anomaly detection possible — you can't detect "unusual" without knowing "normal."

## ATT&CK Coverage

- T1087 — Account Discovery
- T1082 — System Information Discovery
- T1518 — Software Discovery

## Queries

### Installed Packages (Linux)

```sql
-- All installed packages (deb-based)
SELECT name,
       version,
       source,
       arch,
       revision
FROM deb_packages
ORDER BY name;

-- All installed packages (rpm-based)
SELECT name,
       version,
       release,
       arch,
       source
FROM rpm_packages
ORDER BY name;
```

### Installed Software (macOS)

```sql
SELECT name,
       bundle_identifier,
       bundle_short_version AS version,
       path,
       category
FROM apps
ORDER BY name;
```

### Local User Accounts

```sql
-- All local user accounts (cross-platform)
SELECT uid,
       gid,
       username,
       description,
       directory AS home_dir,
       shell,
       type
FROM users
ORDER BY uid;
```

### Group Memberships

```sql
-- Users in privileged groups
SELECT g.groupname,
       g.gid,
       gm.uid,
       u.username
FROM groups g
JOIN user_groups gm ON g.gid = gm.gid
JOIN users u ON gm.uid = u.uid
WHERE g.groupname IN (
    'root', 'sudo', 'wheel', 'admin', 'adm',
    'docker', 'lxd', 'shadow',
    'Administrators', 'Domain Admins', 'Remote Desktop Users'
)
ORDER BY g.groupname, u.username;
```

### Listening Services Inventory

```sql
-- All network listeners with owning process
SELECT lp.port,
       lp.protocol,
       lp.address,
       p.name AS process_name,
       p.path AS process_path,
       p.uid,
       u.username
FROM listening_ports lp
JOIN processes p ON lp.pid = p.pid
LEFT JOIN users u ON p.uid = u.uid
WHERE lp.port > 0
ORDER BY lp.port;
```

### System Information

```sql
-- System identification (cross-platform)
SELECT hostname,
       computer_name,
       cpu_brand,
       cpu_physical_cores,
       cpu_logical_cores,
       physical_memory / 1073741824 AS memory_gb,
       hardware_vendor,
       hardware_model
FROM system_info;
```

### OS Version

```sql
SELECT name,
       version,
       major,
       minor,
       patch,
       build,
       platform,
       arch
FROM os_version;
```

### Startup Items (macOS)

```sql
-- macOS launch agents and daemons
SELECT name,
       path,
       program,
       program_arguments,
       run_at_load,
       username
FROM launchd
WHERE run_at_load = 1
ORDER BY name;
```

## Deployment

```ini
{
  "schedule": {
    "user_inventory": {
      "query": "SELECT uid, username, directory, shell FROM users;",
      "interval": 86400,
      "description": "Daily user account inventory",
      "snapshot": true
    },
    "listening_ports": {
      "query": "SELECT lp.port, lp.protocol, p.name FROM listening_ports lp JOIN processes p ON lp.pid = p.pid WHERE lp.port > 0;",
      "interval": 3600,
      "description": "Hourly listening port inventory"
    },
    "privileged_groups": {
      "query": "SELECT g.groupname, u.username FROM groups g JOIN user_groups gm ON g.gid = gm.gid JOIN users u ON gm.uid = u.uid WHERE g.groupname IN ('root','sudo','wheel','docker','Administrators');",
      "interval": 3600,
      "description": "Privileged group membership"
    }
  }
}
```

## Learn More

- [SOC Operations — Asset Management](https://training.ridgelinecyber.com/courses/m365-security-operations/) — asset inventory and configuration baseline
- [Linux IR — System Enumeration](https://training.ridgelinecyber.com/courses/linux-ir/) — Linux system enumeration during investigations
