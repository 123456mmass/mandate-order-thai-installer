"""Append the mod pak to the installer exe, so the download is one file.

Windows ignores bytes after the end of a PE image, so a trailer costs nothing
and the installer can read its own pak straight out of itself.  The alternative
-- embedding it as a resource -- means a windres pass over a 54 MB blob on every
build, and shipping a loose .pak beside the exe invites exactly the confusion
this whole design avoids.

The footer is 24 bytes: the magic, then the payload's offset and size.  If a
payload is already present it is cut off first, so re-running this on the same
exe replaces the pak rather than stacking a second copy behind the first.

Usage:
    python make_payload.py MOThaiInstaller.exe <mod pak>
"""
import os
import struct
import sys

MAGIC = b'MOTHAIPK'
FOOTER = 24


def strip(path):
    size = os.path.getsize(path)
    if size < FOOTER:
        return
    with open(path, 'rb') as f:
        f.seek(size - FOOTER)
        foot = f.read(FOOTER)
    if foot[:8] != MAGIC:
        return
    off = struct.unpack_from('<Q', foot, 8)[0]
    if 512 <= off < size:
        with open(path, 'r+b') as f:
            f.truncate(off)
        print('  ตัด payload เก่าออก -> %d ไบต์' % off)


def main(exe, pak):
    if not os.path.isfile(exe):
        raise SystemExit('ไม่พบ %s' % exe)
    if not os.path.isfile(pak):
        raise SystemExit('ไม่พบ %s' % pak)

    strip(exe)
    off = os.path.getsize(exe)
    size = os.path.getsize(pak)
    with open(exe, 'ab') as out, open(pak, 'rb') as src:
        while True:
            block = src.read(1 << 20)
            if not block:
                break
            out.write(block)
        out.write(MAGIC + struct.pack('<QQ', off, size))

    total = os.path.getsize(exe)
    print('  แนบ %s (%d ไบต์) ต่อท้าย %s' % (os.path.basename(pak), size, os.path.basename(exe)))
    print('  ผลลัพธ์: %s (%d ไบต์, %.1f MB)' % (exe, total, total / 1048576.0))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2])
