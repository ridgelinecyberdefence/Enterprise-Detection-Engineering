#!/usr/bin/env python3
"""
Extract deployable detection files from the markdown documentation.

Each detection lives as a .md documentation file under its platform directory.
This script pulls the primary rule block out of each doc and writes a bare,
tooling-native file into a parallel rules/ tree, so the rules can be dropped
straight into a pipeline (sigma convert, yarac, suricata -T, SIEM import).

The markdown docs remain the human-facing reference; rules/ is the deployable
mirror. Run this after adding or editing a detection doc to regenerate rules/.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# platform dir -> (fence language to extract, output extension, mode)
# mode: "first" = first matching block; "concat" = all matching blocks joined;
#       "untagged_first" = first bare ``` block (no language tag)
PLATFORMS = {
    "kql":          ("kql",        ".kql",   "first"),
    "sigma":        ("yaml",       ".yml",   "first"),
    "splunk":       ("spl",        ".spl",   "first"),
    "athena":       ("sql",        ".sql",   "first"),
    "powershell":   ("powershell", ".ps1",   "first"),
    "velociraptor": ("yaml",       ".yaml",  "first"),
    "yara":         ("yara",       ".yar",   "first"),
    "suricata":     (None,         ".rules", "untagged_first"),
    "osquery":      ("sql",        ".sql",   "concat"),
}

FENCE = re.compile(r"^```([a-zA-Z0-9]*)\s*$")


def blocks(md_text):
    """Yield (lang, body) for every fenced code block in the file."""
    lines = md_text.splitlines()
    i = 0
    while i < len(lines):
        m = FENCE.match(lines[i])
        if m:
            lang = m.group(1)
            body = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                body.append(lines[i])
                i += 1
            yield lang, "\n".join(body)
        i += 1


def extract_for(platform, md_text):
    lang, _, mode = PLATFORMS[platform]
    found = []
    all_blocks = list(blocks(md_text))
    for blang, body in all_blocks:
        if mode == "untagged_first":
            if blang == "":
                return body, None
        elif blang == lang:
            if mode == "first":
                return body, None
            found.append(body)
    if mode == "concat" and found:
        # Preserve each query's own comment header; join with a blank line.
        return "\n\n".join(found), None
    # Fallback: expected block not found. If the file has exactly one code
    # block, extract it and report the actual language so the caller can name
    # the output correctly and flag the mismatch (a misfiled rule).
    real = [(bl, bd) for bl, bd in all_blocks if bl]
    if len(real) == 1:
        return real[0][1], real[0][0]
    return None, None


def main():
    # Map a detected language back to the correct output extension.
    LANG_EXT = {"yaml": ".yml", "yml": ".yml", "kql": ".kql", "spl": ".spl",
                "sql": ".sql", "powershell": ".ps1", "yara": ".yar"}
    written = 0
    missed = []
    mismatched = []
    for platform, (lang, ext, mode) in PLATFORMS.items():
        src_dir = os.path.join(ROOT, platform)
        if not os.path.isdir(src_dir):
            continue
        for dirpath, _, files in os.walk(src_dir):
            for fn in files:
                if not fn.endswith(".md"):
                    continue
                src = os.path.join(dirpath, fn)
                with open(src, encoding="utf-8") as fh:
                    body, actual_lang = extract_for(platform, fh.read())
                if body is None:
                    missed.append(os.path.relpath(src, ROOT))
                    continue
                use_ext = ext
                if actual_lang is not None:
                    # Fallback fired: the block language differed from the dir.
                    use_ext = LANG_EXT.get(actual_lang.lower(), ext)
                    mismatched.append(
                        f"{os.path.relpath(src, ROOT)} -> block is "
                        f"'{actual_lang}', wrote {use_ext}")
                rel = os.path.relpath(src, ROOT)
                out = os.path.join(ROOT, "rules",
                                   os.path.splitext(rel)[0] + use_ext)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with open(out, "w", encoding="utf-8") as fh:
                    fh.write(body.rstrip() + "\n")
                written += 1
    print(f"extracted: {written} rule files")
    if mismatched:
        print(f"MISFILED ({len(mismatched)}) - block language != directory, "
              f"extracted by actual language (fix the source doc):")
        for m in mismatched:
            print("  ", m)
    if missed:
        print(f"MISSED ({len(missed)}) - no single block to extract:")
        for m in missed:
            print("  ", m)
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
