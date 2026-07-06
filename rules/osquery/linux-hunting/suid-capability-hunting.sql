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
