# Suspicious PE Characteristics

Detects Windows PE files with characteristics commonly associated with malware: high entropy sections (packed/encrypted), suspicious section names, tiny or missing imports, timestamps in the future or distant past, and unsigned executables in system directories. These are structural indicators — the file looks wrong even before behavioral analysis.

## ATT&CK

- **Technique:** T1027.002 — Obfuscated Files: Software Packing
- **Tactic:** Defense Evasion

## Severity

**Medium.** Suspicious PE characteristics are a triage signal, not a definitive indicator. Combined with other signals (unusual location, no signature, recent creation), escalate to High.

## Rule

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
            math.entropy(section.offset, section.size) > 7.2 and
            section.size > 1024
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
        description = "PE with zero or very few imports — likely packed or shellcode wrapper"
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
        $mz = "MZ" at 0

    condition:
        $mz and filesize < 10MB
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

## False Positives

1. **Packed legitimate software.** Some vendors ship UPX-packed installers. Cross-reference with Authenticode signature status.
2. **Go and Rust binaries.** Statically compiled Go/Rust binaries have unusual section layouts and may trigger the entropy rule. Check the compiler signature.
3. **Installers and SFX archives.** Self-extracting archives have high-entropy data sections. Filter by known installer frameworks (NSIS, InnoSetup).
4. **Timestamp anomaly.** Some build systems produce incorrect timestamps. The timestamp rule is low severity for this reason — use as a triage signal only.

## Learn More

- [YARA — Rule Development](https://training.ridgelinecyber.com/short-courses/yara/) — PE module usage and structural analysis
- [Malware Triage — Static Analysis](https://training.ridgelinecyber.com/short-courses/malware-triage/) — PE header analysis and packer identification
- [Windows Forensics — Executable Analysis](https://training.ridgelinecyber.com/courses/windows-forensics/) — forensic analysis of suspicious executables
