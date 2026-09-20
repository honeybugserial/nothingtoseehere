#!/usr/bin/env python3
"""
Reconstruct a clean install tree for each target profile (architecture x Windows
version band) from an innounp-extracted Inno Setup.

innounp extracts architecture/version variants of the same file as
"name,1.ext", "name,2.ext", etc. (collision-disambiguation only -- the number
does NOT map to a fixed architecture). The authoritative mapping lives in the
regenerated install_script.iss [Files] section, in each entry's Check /
MinVersion / OnlyBelowVersion parameters.

This script parses [Files], classifies every entry by architecture and Windows
version band, then rebuilds one tree per distinct *target profile* by simulating
Inno's selection rule (all matching entries are copied in list order; the LAST
match for a destination wins). The result is exactly what the installer would
place on a machine of that profile, with clean filenames and the original
{app}\\... layout preserved.

Usage:
    # Already extracted (folder has {app}\\... and install_script.iss):
    python split_inno_arch.py                 # build trees into ./_sorted
    python split_inno_arch.py --dry-run       # preview, write nothing

    # Or let it extract for you first (innounp must be runnable):
    python split_inno_arch.py --setup RevoUninProSetup.exe --dry-run

Requires only the standard library. Runs on Windows, Linux, or macOS
(path separators in the .iss are normalised, so it parses fine anywhere).
"""

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
from collections import OrderedDict
from datetime import datetime, timezone

PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr"}

NT_NAMES = {
    (5, 0): "win2000", (5, 1): "winxp", (5, 2): "win2003", (6, 0): "winvista",
    (6, 1): "win7", (6, 2): "win8", (6, 3): "win81", (10, 0): "win10",
}


# --------------------------------------------------------------------------- #
# .iss parsing
# --------------------------------------------------------------------------- #

def split_iss_params(line):
    """Split an .iss line on ';' while respecting double-quoted values."""
    parts, buf, in_q = [], [], False
    for ch in line:
        if ch == '"':
            in_q = not in_q
            buf.append(ch)
        elif ch == ';' and not in_q:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


def parse_param(tok):
    """Parse a single 'Key: Value' token; strip surrounding quotes if present."""
    m = re.match(r'^\s*([A-Za-z0-9_]+)\s*:\s*(.*)$', tok)
    if not m:
        return None
    key, val = m.group(1), m.group(2).strip()
    if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
        val = val[1:-1].replace('""', '"')
    return key, val


def arch_from_check(check):
    """Architecture implied by a Check expression. 'any' = no arch constraint."""
    if not check:
        return "any"
    if re.search(r'(?i)\bnot\s+Is64BitInstallMode\b', check):
        return "x86"
    if re.search(r'(?i)\bIs64BitInstallMode\b', check):
        return "x64"
    if re.search(r'(?i)\bnot\s+IsARM64\b', check):
        return "any"          # guard, not a selector
    if re.search(r'(?i)\bIsARM64\b', check):
        return "arm64"
    if re.search(r'(?i)\bIsX64\b', check):
        return "x64"
    if re.search(r'(?i)\bIsX86\b', check):
        return "x86"
    return "any"


def parse_nt_version(value):
    """
    Parse an Inno version field ('0.0,10.0', '6.1', '0,6.0') -> NT version tuple.
    Returns None when there is no NT constraint (0 / 0.0 / blank). The 9x part is
    ignored (these installers are Unicode/NT-only). '6.02' -> (6, 2).
    """
    if not value:
        return None
    parts = value.split(',')
    nt = parts[1] if len(parts) >= 2 else parts[0]
    nt = nt.strip()
    if nt in ("", "0", "0.0"):
        return None
    return tuple(int(x) for x in nt.split('.'))


def nt_ge(a, b):
    """a >= b for NT version tuples (shorter tuple padded with zeros)."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return a >= b


def nt_lt(a, b):
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return a < b


def floor_name(rep):
    if rep[0] == 0:
        return "baseline"
    return NT_NAMES.get(rep, f"nt{rep[0]}.{rep[1]}")


def fmt_nt(rep):
    return f"{rep[0]}.{rep[1]}"


# --------------------------------------------------------------------------- #
# PE machine type
# --------------------------------------------------------------------------- #

def pe_machine(path):
    """Read the PE machine type. Returns x86/x64/arm64/arm, 'machine:0x..', or None."""
    try:
        with open(path, "rb") as f:
            head = f.read(0x40)
            if len(head) < 0x40 or head[0:2] != b"MZ":
                return None
            pe_off = struct.unpack_from("<I", head, 0x3C)[0]
            f.seek(pe_off)
            sig = f.read(6)
            if len(sig) < 6 or sig[0:4] != b"PE\x00\x00":
                return None
            machine = struct.unpack_from("<H", sig, 4)[0]
    except OSError:
        return None
    return {
        0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64",
        0x01C0: "arm", 0x01C4: "arm",
    }.get(machine, f"machine:0x{machine:X}")


# --------------------------------------------------------------------------- #
# Core
# --------------------------------------------------------------------------- #

class Entry:
    __slots__ = ("order", "source", "dest_dir", "dest_name", "dest",
                 "arch", "min_nt", "below_nt", "check")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def parse_files_section(iss_path):
    with open(iss_path, "r", encoding="utf-8-sig") as f:
        text = f.read()

    in_files, file_lines = False, []
    for line in text.splitlines():
        s = line.strip()
        if re.match(r'^\[Files\]\s*$', s, re.I):
            in_files = True
            continue
        if in_files and s.startswith('['):
            break
        if in_files and s:
            file_lines.append(line)

    entries, order = [], 0
    for line in file_lines:
        params = {}
        for tok in split_iss_params(line):
            p = parse_param(tok)
            if p:
                params[p[0]] = p[1]
        if "Source" not in params:
            continue

        source = params["Source"].replace("/", "\\")
        dest_dir = params.get("DestDir", "").replace("/", "\\") or source.rsplit("\\", 1)[0]
        dest_name = params.get("DestName") or source.rsplit("\\", 1)[-1]
        check = params.get("Check", "")

        entries.append(Entry(
            order=order,
            source=source,
            dest_dir=dest_dir,
            dest_name=dest_name,
            dest=dest_dir + "\\" + dest_name,
            arch=arch_from_check(check),
            min_nt=parse_nt_version(params.get("MinVersion", "")),
            below_nt=parse_nt_version(params.get("OnlyBelowVersion", "")),
            check=check,
        ))
        order += 1
    return entries


def included(entry, arch, rep):
    if entry.arch != "any" and entry.arch != arch:
        return False
    if entry.min_nt and not nt_ge(rep, entry.min_nt):
        return False
    if entry.below_nt and not nt_lt(rep, entry.below_nt):
        return False
    return True


def resolve_selection(entries, arch, rep):
    """Ordered map dest -> entry, applying Inno's last-match-wins rule."""
    result = OrderedDict()
    for e in entries:
        if included(e, arch, rep):
            result.pop(e.dest, None)   # keep insertion order = last position
            result[e.dest] = e
    return result


def build_profiles(entries):
    arches = sorted({e.arch for e in entries if e.arch != "any"}) or ["any"]

    breakpoints = sorted({v for e in entries for v in (e.min_nt, e.below_nt) if v})
    reps = [(0, 0)] + breakpoints

    profiles = []
    for arch in arches:
        seen = set()
        for rep in reps:
            sel = resolve_selection(entries, arch, rep)
            sig = tuple(sorted((d, e.source) for d, e in sel.items()))
            if sig in seen:
                continue
            seen.add(sig)
            upper = next((bp for bp in breakpoints if bp > rep), None)
            label = ("all" if arch == "any" else arch) + "-" + floor_name(rep)
            profiles.append(dict(name=label, arch=arch, rep=rep, upper=upper, sel=sel))
    return arches, breakpoints, profiles


def preflight(entries, extract_root):
    """Return (warnings, pe_cache). Flags missing files and PE/arch mismatches."""
    warnings, pe_cache = [], {}

    def cached_pe(rel):
        if rel not in pe_cache:
            full = os.path.join(extract_root, rel.replace("\\", os.sep))
            pe_cache[rel] = pe_machine(full) if os.path.isfile(full) else None
        return pe_cache[rel]

    for e in sorted(entries, key=lambda x: x.order):
        full = os.path.join(extract_root, e.source.replace("\\", os.sep))
        if not os.path.isfile(full):
            warnings.append(f"MISSING source on disk: {e.source}")
            continue
        ext = os.path.splitext(e.dest_name)[1].lower()
        if ext in PE_EXTS and e.arch in ("x86", "x64", "arm64"):
            pe = cached_pe(e.source)
            if pe and pe != e.arch:
                warnings.append(
                    f"PE/arch mismatch: {e.source} classified '{e.arch}' but PE machine is '{pe}'")
    return warnings


# --------------------------------------------------------------------------- #
# Reporting / writing
# --------------------------------------------------------------------------- #

def profile_range(p, long=False):
    if p["upper"]:
        return (f"NT {fmt_nt(p['rep'])} up to (but not including) {fmt_nt(p['upper'])}"
                if long else f"NT {fmt_nt(p['rep'])} .. <{fmt_nt(p['upper'])}")
    return f"NT {fmt_nt(p['rep'])} and up" if long else f"NT >= {fmt_nt(p['rep'])}"


def print_report(entries, arches, breakpoints, profiles, dead, warnings, iss_path):
    print(f"\nParsed {len(entries)} [Files] entries from: {iss_path}")
    print(f"Architectures : {', '.join(arches)}")
    print("NT breakpoints: " +
          (", ".join(fmt_nt(b) for b in breakpoints) if breakpoints
           else "(none - no version-gated files)"))
    print(f"Profiles      : {len(profiles)}")

    print("\nResolved target profiles")
    for p in profiles:
        print(f"  {p['name']:<16} {p['arch']:<6} {profile_range(p):<22} {len(p['sel'])} files")
        for dest, e in p["sel"].items():
            leaf = e.source.rsplit("\\", 1)[-1]
            if re.search(r',\d+\.', leaf):
                print(f"      {e.dest_name:<22} <- {leaf}")

    if dead:
        print("\nNever-selected variants (present but always overwritten)")
        for d in dead:
            print(f"  {d}")

    if warnings:
        print("\nWarnings")
        for w in warnings:
            print(f"  {w}")


def write_trees(extract_root, output_root, profiles, dead, warnings, iss_path, force):
    if os.path.exists(output_root):
        if not force:
            ans = input(f"OutputRoot '{output_root}' exists. Delete and recreate? [y/N] ")
            if ans.strip().lower() not in ("y", "yes"):
                print("Aborted.")
                return
        shutil.rmtree(output_root)
    os.makedirs(output_root)

    summary = [
        f"Source iss : {iss_path}",
        f"Generated  : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}",
        f"Profiles   : {len(profiles)}",
        "",
    ]

    for p in profiles:
        prof_dir = os.path.join(output_root, p["name"])
        manifest = [
            f"Profile      : {p['name']}",
            f"Architecture : {p['arch']}",
            f"Windows      : {profile_range(p, long=True)}",
            f"File count   : {len(p['sel'])}",
            "",
            "Destination  <-  source variant",
        ]
        for dest, e in p["sel"].items():
            src_full = os.path.join(extract_root, e.source.replace("\\", os.sep))
            dst_full = os.path.join(prof_dir, e.dest.replace("\\", os.sep))
            if not os.path.isfile(src_full):
                manifest.append(f"  [MISSING] {e.dest}  <-  {e.source}")
                continue
            os.makedirs(os.path.dirname(dst_full), exist_ok=True)
            shutil.copy2(src_full, dst_full)
            manifest.append(f"  {e.dest}  <-  {e.source}")

        os.makedirs(prof_dir, exist_ok=True)
        with open(os.path.join(prof_dir, "_PROFILE.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(manifest) + "\n")
        summary.append(f"{p['name']}  ({p['arch']}, {profile_range(p, long=True)})  - {len(p['sel'])} files")

    if dead:
        summary += ["", "Never-selected variants:"] + [f"  {d}" for d in dead]
    if warnings:
        summary += ["", "Warnings:"] + [f"  {w}" for w in warnings]

    with open(os.path.join(output_root, "_SUMMARY.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(summary) + "\n")

    print(f"\nDone. {len(profiles)} profiles written to: {output_root}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Split an innounp extraction into one clean tree per target profile.")
    ap.add_argument("--extract-root", default=".",
                    help="Folder containing the innounp output and install_script.iss (default: .).")
    ap.add_argument("--setup",
                    help="Original Setup .exe; if given and no .iss is present yet, it is extracted first.")
    ap.add_argument("--innounp", default="innounp",
                    help="Path to the innounp executable (default: innounp on PATH).")
    ap.add_argument("--iss",
                    help="Path to install_script.iss (default: <extract-root>/install_script.iss).")
    ap.add_argument("--output-root",
                    help="Where to write the per-profile trees (default: <extract-root>/_sorted).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Resolve and print the plan; copy nothing.")
    ap.add_argument("--force", action="store_true",
                    help="Overwrite an existing output root without prompting.")
    args = ap.parse_args(argv)

    extract_root = os.path.abspath(args.extract_root)
    iss_path = args.iss or os.path.join(extract_root, "install_script.iss")
    output_root = args.output_root or os.path.join(extract_root, "_sorted")

    if args.setup and not os.path.isfile(iss_path):
        setup_full = os.path.abspath(args.setup)
        os.makedirs(extract_root, exist_ok=True)
        print(f"\nExtracting with innounp into: {extract_root}")
        # Extract in-place (cwd = extract_root); matches `innounp -x setup.exe`.
        rc = subprocess.call([args.innounp, "-x", setup_full], cwd=extract_root)
        if rc != 0:
            sys.exit(f"innounp exited with code {rc}")

    if not os.path.isfile(iss_path):
        sys.exit(f"install_script.iss not found at '{iss_path}'. "
                 f"Use --iss to point at it, or --setup to extract first.")

    entries = parse_files_section(iss_path)
    if not entries:
        sys.exit(f"No [Files] entries parsed from {iss_path}.")

    arches, breakpoints, profiles = build_profiles(entries)

    selected = {e.source for p in profiles for e in p["sel"].values()}
    dead = sorted({e.source for e in entries
                   if e.source not in selected and re.search(r',\d+\.', e.source.rsplit("\\", 1)[-1])})

    warnings = preflight(entries, extract_root)

    print_report(entries, arches, breakpoints, profiles, dead, warnings, iss_path)

    if args.dry_run:
        print(f"\nDRY RUN - nothing written. Output would go to: {output_root}")
        return

    write_trees(extract_root, output_root, profiles, dead, warnings, iss_path, args.force)


if __name__ == "__main__":
    main()
