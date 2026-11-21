#!/usr/bin/env python3
"""Build a Kirin710 POT-ONLY FDT catalog from 40 compiled .dtb files.

Run from Kbuild after standard DTS->DTB compilation.  Each board DTB is
embedded without modification as the dtb-data property of its catalog entry.
The catalog is an FDT container, NOT a DTB that can be booted by Linux until
uniLoader selects and extracts a member.
"""

import argparse
from pathlib import Path
import struct
import subprocess
import sys

MAGIC = 0xD00DFEED
FAMILY = "POT"
EXPECTED_COUNT = 40



def fdt_identity(blob):
    if len(blob) < 56:
        raise ValueError("DTB header or reservation table truncated")
    (magic, total, off_struct, off_strings, off_mem, version, last,
     _bootcpu, len_strings, len_struct) = struct.unpack_from(">10I", blob)
    if magic != MAGIC or total != len(blob) or version < 16 or last > 17:
        raise ValueError("invalid FDT magic/header/totalsize")
    if (off_struct + len_struct > total or off_strings + len_strings > total
            or off_mem + 16 > total):
        raise ValueError("FDT section outside totalsize")
    strings = blob[off_strings:off_strings + len_strings]
    pos, end = off_struct, off_struct + len_struct
    nodes = []
    boardid, boardname = None, None
    saw_end = False
    while pos + 4 <= end:
        token, = struct.unpack_from(">I", blob, pos)
        pos += 4
        if token == 1:  # FDT_BEGIN_NODE
            zero = blob.find(b"\0", pos, end)
            if zero < 0:
                raise ValueError("unterminated FDT node")
            nodes.append(blob[pos:zero].decode("ascii"))
            pos = (zero + 4) & ~3
        elif token == 2:  # FDT_END_NODE
            if not nodes:
                raise ValueError("unbalanced FDT node")
            nodes.pop()
        elif token == 3:  # FDT_PROP
            if pos + 8 > end:
                raise ValueError("truncated FDT property")
            length, nameoff = struct.unpack_from(">II", blob, pos)
            pos += 8
            if pos + length > end or nameoff >= len(strings):
                raise ValueError("FDT property out of bounds")
            nameend = strings.find(b"\0", nameoff)
            if nameend < 0:
                raise ValueError("unterminated FDT property name")
            key = strings[nameoff:nameend]
            val = blob[pos:pos + length]
            pos = (pos + length + 3) & ~3
            if nodes == ["", "rootparam"]:
                if key == b"hisi,boardid":
                    if boardid is not None or length != 16:
                        raise ValueError("duplicate/malformed boardid")
                    boardid = struct.unpack(">4I", val)
                elif key == b"hisi,boardname":
                    if (boardname is not None or not val.endswith(b"\0")
                            or val.count(b"\0") != 1):
                        raise ValueError("duplicate/malformed boardname")
                    boardname = val[:-1].decode("ascii")
        elif token == 4:  # FDT_NOP
            continue
        elif token == 9:  # FDT_END
            saw_end = True
            break
        else:
            raise ValueError("invalid FDT token")
    if not saw_end or nodes or boardid is None or boardname is None:
        raise ValueError("missing FDT END or /rootparam identity")
    return boardid, boardname


def generate_catalog(output, dtbs, dtc, max_size):
    if len(dtbs) != EXPECTED_COUNT:
        raise ValueError("%s catalog expects exactly %d DTBs, received %d" %
                         (FAMILY, EXPECTED_COUNT, len(dtbs)))
    found = {}
    seen_paths = set()
    for path in dtbs:
        path = path.resolve()
        if path in seen_paths:
            raise ValueError("duplicate input file: %s" % path)
        seen_paths.add(path)
        if path.suffix.lower() != ".dtb" or path == output:
            raise ValueError("invalid input DTB: %s" % path)
        # Kbuild stores members under <obj>/sne|pot|mar/*.dtb but writes
        # the catalog into <obj>/<family>_catalog.dtb. Keep supporting
        # the older standalone layout with all inputs beside the output.
        expected_subdir = output.parent / FAMILY.lower()
        if path.parent == output.parent:
            incbin_name = path.name
        elif path.parent == expected_subdir:
            incbin_name = FAMILY.lower() + "/" + path.name
        else:
            raise ValueError("input DTB must be beside catalog or in %s: %s" %
                             (expected_subdir, path))
        raw = path.read_bytes()
        boardid, name = fdt_identity(raw)
        kind = name.split('_', 1)[0].split('-', 1)[0].upper()
        if kind != FAMILY:
            raise ValueError("%s belongs to %s, expected %s: %s" %
                             (path.name, kind, FAMILY, name))
        if not name or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-" for c in name):
            raise ValueError("unsafe board name %r in %s" % (name, path))
        if boardid in found:
            raise ValueError("duplicate boardid %r" % (boardid,))
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("%s exceeds 2 MiB per-board workspace" % path)
        found[boardid] = (name, path, len(raw), incbin_name)

    # Generate alongside the output; /incbin/ refers to compiled DTBs
    # in the same directory or the family's Kbuild subdirectory.
    dts = output.with_suffix(".dts")
    lines = [
        "/dts-v1/;", "", "/ {",
        '\tcompatible = "huawei,kirin710-dtb-catalog-v1";',
        '\tmodel = "Kirin710 EMUI10 POT DTB catalog";',
        "\tkirin710,dtb-catalog {",
        '\t\tcompatible = "huawei,kirin710-dtb-catalog-v1";',
    ]
    for boardid, (name, path, size, incbin_name) in sorted(found.items()):
        node = "-".join(map(str, boardid))
        lines.extend([
            "\t\tboard-%s {" % node,
            "\t\t\thisi,boardid = <%s>;" % " ".join(map(str, boardid)),
            '\t\t\tboard-name = "%s";' % name,
            '\t\t\tdtb-data = /incbin/("%s");' % incbin_name,
            "\t\t};",
        ])
    lines.extend(["\t};", "};", ""])
    dts.write_text("\n".join(lines))

    # DTC compiles only the catalog wrapper. Every member DTB is included
    # byte-for-byte using /incbin/; no second DTS->DTB compilation occurs.
    temporary_output = output.with_name(output.name + ".tmp")
    try:
        result = subprocess.run(
            [str(dtc), "-I", "dts", "-O", "dtb", "-o", str(temporary_output), str(dts)],
            cwd=str(output.parent),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode:
            raise RuntimeError("catalog dtc failed:\n%s" % result.stderr)
        size = temporary_output.stat().st_size
        if max_size and size > max_size:
            raise ValueError("catalog exceeds limit: %d > %d bytes" % (size, max_size))
        temporary_output.replace(output)
    finally:
        temporary_output.unlink(missing_ok=True)
    print("Kirin710 %s catalog: %d boards, %d bytes" %
          (FAMILY, len(found), size))
    for boardid, (name, _path, n, _incbin) in sorted(found.items()):
        print("  %-16s %s %d bytes" % (name, ".".join(map(str, boardid)), n))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--dtc", required=True, type=Path)
    inputs = p.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--dtb", action="append", type=Path,
                        help="repeat once per compiled %s DTB" % FAMILY)
    inputs.add_argument("--dtb-dir", type=Path,
                        help="directory containing compiled %s *.dtb files" % FAMILY)
    p.add_argument("--max-size", type=int, default=64 * 1024 * 1024,
                   help="max catalog bytes (default 64 MiB, same as kirin710-fdt.c)")
    args = p.parse_args()
    out = args.output.resolve()
    dtc = args.dtc.resolve()
    if not dtc.is_file():
        raise ValueError("dtc not found: %s" % dtc)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.dtb_dir:
        source_dir = args.dtb_dir.resolve()
        if not source_dir.is_dir():
            raise ValueError("DTB directory not found: %s" % source_dir)
        dtbs = sorted(path for path in source_dir.glob("*.dtb")
                      if not path.name.lower().endswith("_catalog.dtb"))
    else:
        dtbs = args.dtb
    generate_catalog(out, dtbs, dtc, args.max_size)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as exc:
        sys.exit("ERROR: %s" % exc)
