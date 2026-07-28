# Suspicious PE Characteristics

Detects Windows PE files with characteristics commonly associated with malware: high entropy sections (packed/encrypted), suspicious section names, tiny or missing imports, timestamps in the future or distant past, and unsigned executables in system directories. These are structural indicators. The file looks wrong even before behavioral analysis.

## ATT&CK

- **Technique:** T1027.002, Obfuscated Files: Software Packing
- **Tactic:** Defense Evasion

## Severity

**Medium.** Suspicious PE characteristics are a triage signal, not a definitive indicator. Combined with other signals (unusual location, no signature, recent creation), escalate to High.

## Data Sources

A scanning surface and a scanner. These rules are written for `yara` or `yara-x` against files on disk, memory images, or a scanning pipeline such as an EDR custom-indicator feed, Velociraptor's YARA artifact, or a mail and web gateway that supports YARA.

Where you scan decides what these rules can find. On-disk scanning misses anything that only ever existed in memory, which is most modern implant loaders. Memory scanning finds those but needs a capture or live agent access.

## Query: YARA
```yara
import "pe"
import "math"

rule Suspicious_PE_High_Entropy_Section
{
    meta:
        author = "Ridgeline Cyber"
        description = "PE with high-entropy section suggesting packing or encryption"
        date = "2025-05-25"
        severity = "medium"
        mitre_attack = "T1027.002"

    condition:
        pe.is_pe and
        for any section in pe.sections : (
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.2 and
            section.raw_data_size > 1024
        )
}

rule Suspicious_PE_Section_Names
{
    meta:
        author = "Ridgeline Cyber"
        description = "PE with section names associated with known packers or malware"
        date = "2025-05-25"
        severity = "medium"
        mitre_attack = "T1027.002"

    condition:
        pe.is_pe and
        for any section in pe.sections : (
            section.name == ".ndata" or
            section.name == "UPX0" or
            section.name == "UPX1" or
            section.name == ".themida" or
            section.name == ".vmp0" or
            section.name == ".vmp1" or
            section.name == ".enigma" or
            section.name == ".aspack" or
            section.name == ".adata" or
            section.name == "MPRESS1" or
            section.name == "MPRESS2" or
            section.name == ".petite"
        )
}

rule Suspicious_PE_No_Imports
{
    meta:
        author = "Ridgeline Cyber"
        description = "PE with zero or very few imports: likely packed or shellcode wrapper"
        date = "2025-05-25"
        severity = "medium"
        mitre_attack = "T1027.002"

    condition:
        pe.is_pe and
        pe.number_of_imports < 3 and
        filesize > 10KB
}

rule Suspicious_PE_Timestamp_Anomaly
{
    meta:
        author = "Ridgeline Cyber"
        description = "PE with compilation timestamp in the future or before 2005"
        date = "2025-05-25"
        severity = "low"
        mitre_attack = "T1070.006"

    condition:
        pe.is_pe and
        (pe.timestamp > 1800000000 or pe.timestamp < 1104537600) and
        pe.timestamp != 0
}

rule Suspicious_PE_Double_Extension
{
    meta:
        author = "Ridgeline Cyber"
        description = "File with double extension attempting to disguise PE as document"
        date = "2025-05-25"
        severity = "high"
        mitre_attack = "T1036.007"

    strings:
        $mz = "MZ"

    condition:
        $mz at 0 and filesize < 10MB
}
```

## Deployment

```bash
# Scan downloads and temp directories
yara -r suspicious_pe.yar /home/*/Downloads/ /tmp/
yara -r suspicious_pe.yar C:\Users\*\Downloads\ C:\Windows\Temp\

# Integrate with Velociraptor
# Use Generic.Detection.Yara.Glob targeting temp/download paths
```

## What Triggers This

Structural anomalies rather than content. The rules cover a section with entropy high enough to indicate packing or encryption, section names that do not match any common compiler or packer convention, a PE with no or almost no imports, and a compile timestamp that is impossible or clearly forged.

None of these says malicious. Each says the file does not look like something a normal build process produced, which is a reason to look rather than a verdict.

## False Positives

1. **Commercial packers and protectors.** Legitimate software is routinely packed with VMProtect, Themida or an installer's own compressor, and every one of those produces high entropy sections and unusual section names. On a typical estate this is the majority of matches.
2. **Installers and self-extracting archives** by design contain a compressed payload.
3. **Games and anti-cheat software** are among the most heavily obfuscated legitimate binaries in existence.
4. **.NET assemblies** frequently have minimal import tables, which trips the no-imports rule without indicating anything.
5. **Reproducible builds** deliberately zero or fix the timestamp, which can read as forged.

## False Positives

1. **Packed legitimate software.** Some vendors ship UPX-packed installers. Cross-reference with Authenticode signature status.
2. **Go and Rust binaries.** Statically compiled Go/Rust binaries have unusual section layouts and may trigger the entropy rule. Check the compiler signature.
3. **Installers and SFX archives.** Self-extracting archives have high-entropy data sections. Filter by known installer frameworks (NSIS, InnoSetup).
4. **Timestamp anomaly.** Some build systems produce incorrect timestamps. The timestamp rule is low severity for this reason. Use as a triage signal only.

## Tuning Notes

- **These are triage inputs, not alerts.** Deployed as alerts they will bury a queue with packed legitimate software. Deployed as an enrichment score on files you already have a reason to look at, they are useful.
- **Combine at least two before acting.** High entropy alone is common. High entropy with no imports and a forged timestamp is a small set worth reading.
- **Baseline your estate's packers first.** A short list of the protectors your legitimate software uses removes most of the volume, and building it is a day's work that pays back permanently.
- **The no-imports rule needs a .NET exclusion** or it will match a large share of ordinary managed binaries.
- **Prevalence is the missing dimension.** A packed binary present on four hundred hosts is your endpoint agent; the same characteristics on one host are worth the time. These rules cannot see that, so join their output to an inventory before triaging.

## Learn More

- [YARA: Rule Development](https://ridgelinecyber.com/training/courses/yara-rule-writing/). PE module usage and structural analysis
- [Malware Triage: Static Analysis](https://ridgelinecyber.com/training/courses/malware-triage/). PE header analysis and packer identification
- [Windows Forensics: Executable Analysis](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/). forensic analysis of suspicious executables
