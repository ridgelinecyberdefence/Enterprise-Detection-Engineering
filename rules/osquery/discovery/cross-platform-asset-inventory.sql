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

SELECT name,
       bundle_identifier,
       bundle_short_version AS version,
       path,
       category
FROM apps
ORDER BY name;

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

SELECT name,
       version,
       major,
       minor,
       patch,
       build,
       platform,
       arch
FROM os_version;

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
