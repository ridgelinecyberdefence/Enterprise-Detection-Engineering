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
        $mz = "MZ"

    condition:
        $mz at 0 and filesize < 10MB
}
