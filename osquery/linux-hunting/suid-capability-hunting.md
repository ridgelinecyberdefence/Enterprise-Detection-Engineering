# Linux SUID Binary and Capability Hunting

osquery queries for discovering SUID/SGID binaries and files with elevated Linux capabilities. These are the privilege escalation paths attackers enumerate first. Any unexpected SUID binary or capability is a potential root escalation.

## ATT&CK Coverage

- T1548.001 - Abuse Elevation Control Mechanism: SUID/SGID
- T1068 - Exploitation for Privilege Escalation

## Queries

### All SUID Binaries

```sql
-- Every SUID binary on the system
SELECT path,
       filename,
       uid,
       gid,
       mode,
       size,
       mtime,
       datetime(mtime, 'unixepoch') AS modified
FROM suid_bin
ORDER BY mtime DESC;
```

### Unexpected SUID Binaries (Not in Standard Paths)

```sql
-- SUID binaries outside /usr/bin, /usr/sbin, /bin, /sbin
SELECT path,
       filename,
       uid,
       gid,
       mode,
       size,
       mtime,
       datetime(mtime, 'unixepoch') AS modified
FROM suid_bin
WHERE path NOT LIKE '/usr/bin/%'
  AND path NOT LIKE '/usr/sbin/%'
  AND path NOT LIKE '/bin/%'
  AND path NOT LIKE '/sbin/%'
  AND path NOT LIKE '/usr/lib/%'
  AND path NOT LIKE '/usr/libexec/%'
  AND path NOT LIKE '/snap/%'
ORDER BY mtime DESC;
```

### Recently Modified SUID Binaries

```sql
-- SUID binaries modified in the last 30 days (should be rare)
SELECT path,
       filename,
       uid,
       gid,
       mode,
       size,
       mtime,
       datetime(mtime, 'unixepoch') AS modified
FROM suid_bin
WHERE mtime > (strftime('%s', 'now') - 2592000)
ORDER BY mtime DESC;
```

### GTFOBins SUID Candidates

```sql
-- SUID binaries that have known GTFOBins privilege escalation methods
SELECT path,
       filename,
       mode,
       mtime
FROM suid_bin
WHERE filename IN (
    'aria2c', 'arp', 'ash', 'awk', 'base32', 'base64', 'bash',
    'busybox', 'cat', 'chmod', 'chown', 'cp', 'csh', 'curl',
    'cut', 'dash', 'date', 'dd', 'dialog', 'diff', 'dmesg',
    'docker', 'ed', 'emacs', 'env', 'expand', 'expect', 'facter',
    'file', 'find', 'flock', 'fmt', 'fold', 'gdb', 'gimp',
    'git', 'grep', 'head', 'ionice', 'ip', 'jjs', 'join',
    'journalctl', 'ksh', 'ld.so', 'less', 'logsave', 'ltrace',
    'lua', 'make', 'man', 'mawk', 'more', 'mv', 'nano', 'nawk',
    'nice', 'nl', 'nmap', 'node', 'od', 'openssl', 'perl',
    'pg', 'php', 'pic', 'pico', 'python', 'python2', 'python3',
    'readelf', 'restic', 'rev', 'rlwrap', 'rsync', 'run-parts',
    'rview', 'rvim', 'scp', 'sed', 'setarch', 'shuf', 'socat',
    'sort', 'sqlite3', 'ssh', 'start-stop-daemon', 'stdbuf',
    'strace', 'strings', 'tail', 'tar', 'taskset', 'tclsh',
    'tee', 'tftp', 'time', 'timeout', 'ul', 'unexpand', 'uniq',
    'unshare', 'vi', 'vim', 'watch', 'wget', 'wish', 'xargs',
    'xxd', 'zip', 'zsh'
)
ORDER BY filename;
```

### Files with Elevated Capabilities

```sql
-- Files with Linux capabilities set (alternative to SUID for privesc)
SELECT path,
       filename,
       cap_effective,
       cap_inheritable,
       cap_permitted
FROM file
WHERE (
    path LIKE '/usr/bin/%'
    OR path LIKE '/usr/sbin/%'
    OR path LIKE '/usr/local/bin/%'
    OR path LIKE '/opt/%'
)
AND (cap_effective != '' OR cap_permitted != '')
ORDER BY path;
```

### World-Writable Files in System Paths

```sql
-- World-writable files in system directories (modification target)
SELECT path,
       filename,
       mode,
       uid,
       gid,
       size,
       mtime
FROM file
WHERE (
    path LIKE '/usr/bin/%'
    OR path LIKE '/usr/sbin/%'
    OR path LIKE '/usr/local/bin/%'
    OR path LIKE '/etc/%'
)
AND mode LIKE '%7'
AND type = 'regular'
ORDER BY path;
```

## Deployment

```ini
{
  "schedule": {
    "suid_audit": {
      "query": "SELECT path, filename, mode, mtime FROM suid_bin WHERE path NOT LIKE '/usr/bin/%' AND path NOT LIKE '/usr/sbin/%' AND path NOT LIKE '/bin/%' AND path NOT LIKE '/sbin/%' AND path NOT LIKE '/usr/lib/%' AND path NOT LIKE '/snap/%';",
      "interval": 3600,
      "description": "Non-standard SUID binaries",
      "snapshot": true
    },
    "gtfobins_suid": {
      "query": "SELECT path, filename, mode FROM suid_bin WHERE filename IN ('python','python3','vim','find','nmap','bash','less','tar','gdb','perl','ruby','env','awk','sed','cp','mv','docker','git','node','php','socat','strace','ssh');",
      "interval": 3600,
      "description": "SUID binaries with known GTFOBins exploits"
    }
  }
}
```

## Learn More

- [Linux IR: Privilege Escalation Analysis](https://ridgelinecyber.com/training/courses/linux-endpoint-investigation/). SUID, capability, and sudo forensics
- [Offensive Security for Defenders: Linux Privesc](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/). GTFOBins and capability abuse
