# Ransomware Impact Assessment

Assesses ransomware impact on an endpoint by scanning for encrypted files, ransom notes, shadow copy deletion, and encryption artifacts. Quantifies the damage: how many files were encrypted, which directories were affected, what file types were targeted, and whether recovery points still exist.

## ATT&CK Coverage

- T1486 — Data Encrypted for Impact
- T1490 — Inhibit System Recovery
- T1489 — Service Stop

## Artifact

```yaml
name: Custom.Windows.Investigation.RansomwareImpact
description: |
  Assess ransomware damage by scanning for encrypted files, ransom
  notes, shadow copy status, and encryption indicators. Quantifies
  impact by directory and file type.

type: CLIENT

parameters:
  - name: EncryptedExtensions
    description: Regex of known ransomware file extensions
    default: "\\.(locked|encrypted|enc|crypt|cry|cry6|cerber|locky|zepto|odin|osiris|zzzzz|micro|mp3$|vvv|ecc|ezz|exx|abc|aaa|bbb|xtbl|breaking_bad|darkness|enigma|onion|wallet|dharma|arena|java|bip|gamma|combo|arrow|audit|cezar|cmb|money|bkp|btc|heets|qwex|pedro|roger|rdp|harma|wiki|deal|cruz|dcrtr|adobe|aqva|bear|duck|STOP|djvu|rumba|gero|hese|karl|nols|werd|ndarod|moka|gif|kvag|bora|reco|kuus|geno|reig|tirp|peet|ghas|hajd|maql|nqhd|ygkz|mljx|lmas|qapo|qpss|dfwe|bbnm|hhwq|jjll|mmvb|oodt|ppvs|qqkk|watz|waqa|wiaw)$"
  - name: RansomNoteNames
    description: Regex of common ransom note filenames
    default: "(?i)(readme.*\\.txt|readme.*\\.html|how.*decrypt|how.*recover|restore.*files|decrypt.*instructions|ransom.*note|_readme\\.txt|DECRYPT|HOW_TO_DECRYPT|ATTENTION|RECOVERY|HELP_DECRYPT|YOUR_FILES)"

sources:
  - name: RansomNotes
    description: Ransom notes found on the file system
    query: |
      SELECT FullPath, Name, Size,
             Mtime AS Modified,
             Ctime AS Created,
             "Ransom Note" AS Finding
      FROM glob(globs="C:\\Users\\**")
      WHERE Name =~ RansomNoteNames
        AND NOT IsDir
      LIMIT 50

  - name: EncryptedFileSample
    description: Sample of files with ransomware extensions
    query: |
      SELECT FullPath, Name, Size,
             Mtime AS Modified,
             "Encrypted File" AS Finding
      FROM glob(globs="C:\\Users\\**")
      WHERE Name =~ EncryptedExtensions
        AND NOT IsDir
      LIMIT 200

  - name: ImpactSummary
    description: Count of encrypted files by directory
    query: |
      SELECT dirname(path=FullPath) AS Directory,
             count() AS EncryptedCount,
             format(format="%.2f MB", args=sum(item=Size) / 1048576.0) AS TotalSize
      FROM glob(globs="C:\\Users\\**")
      WHERE Name =~ EncryptedExtensions
        AND NOT IsDir
      GROUP BY Directory
      ORDER BY EncryptedCount DESC
      LIMIT 50

  - name: ShadowCopyStatus
    description: Volume Shadow Copy availability
    query: |
      SELECT * FROM execve(argv=["vssadmin", "list", "shadows"])

  - name: RecoveryIndicators
    description: Evidence of recovery inhibition
    query: |
      LET BCDEvents = SELECT
             System.TimeCreated.SystemTime AS Timestamp,
             EventData AS Data,
             "BCD Modification" AS Finding
      FROM parse_evtx(
        filename="C:\\Windows\\System32\\winevt\\Logs\\System.evtx"
      )
      WHERE System.EventID.Value = 7040
        AND str(str=EventData) =~ "(?i)(vss|ShadowCopy|backup)"

      LET PrefetchDeletion = SELECT Name, Mtime AS LastRun,
             "Recovery Tool Executed" AS Finding
      FROM glob(globs="C:\\Windows\\Prefetch\\*.pf")
      WHERE Name =~ "(?i)(VSSADMIN|WMIC.*SHADOWCOPY|BCDEDIT|WBADMIN)"

      SELECT * FROM chain(a=BCDEvents, b=PrefetchDeletion)
```

## Immediate Actions After Running

1. If shadow copies exist → begin recovery immediately before further damage
2. Note the ransom note content (DO NOT navigate to attacker URLs from a production machine)
3. Document the encrypted file extensions — these identify the ransomware family
4. Check `ImpactSummary` for which directories are affected — helps prioritize recovery
5. Feed the encrypted extension into threat intelligence to identify the variant and check for available decryptors

## Learn More

- [Incident Response — Ransomware Response](https://training.ridgelinecyber.com/courses/practical-incident-response/) — ransomware containment, assessment, and recovery
- [Windows Forensics — Ransomware Analysis](https://training.ridgelinecyber.com/courses/windows-forensics/) — forensic analysis of ransomware artifacts
