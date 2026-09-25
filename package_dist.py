"""Assemble the release zip: one installer, its licences, and the README.

Run this after building the installer and appending the payload:

    g++ ... -o MOThaiInstaller.exe MOThaiInstaller.cpp
    python make_payload.py MOThaiInstaller.exe ../tools/mod_pakchunk5000_s3-Windows.pak
    python package_dist.py

The zip is stored uncompressed on purpose.  Almost all of its bytes are the pak
inside the installer, which UnrealPak already compressed with zlib, so deflating
again buys a fraction of a percent and costs a minute of CPU.
"""
import hashlib
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DIST = os.path.join(ROOT, 'dist')
EXE = os.path.join(HERE, 'MOThaiInstaller.exe')

sys.stdout.reconfigure(encoding='utf-8')

VERSION = '1.0'
NAME = 'MandateOrder-ThaiMod-v%s' % VERSION


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def main():
    if not os.path.isfile(EXE):
        raise SystemExit('ยังไม่ได้คอมไพล์ MOThaiInstaller.exe')
    if not os.path.isdir(os.path.join(DIST, 'licenses')):
        raise SystemExit('ไม่พบ dist/licenses')

    files = [('MOThaiInstaller.exe', EXE)]
    for root, _dirs, names in os.walk(os.path.join(DIST, 'licenses')):
        for n in sorted(names):
            p = os.path.join(root, n)
            files.append((os.path.relpath(p, DIST).replace(os.sep, '/'), p))
    for n in sorted(os.listdir(DIST)):
        p = os.path.join(DIST, n)
        if os.path.isfile(p) and n.lower().endswith('.txt'):
            files.append((n, p))

    out = os.path.join(DIST, NAME + '.zip')
    if os.path.exists(out):
        os.remove(out)
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_STORED) as z:
        for rel, p in files:
            z.write(p, NAME + '/' + rel)
            print('  %-46s %8.2f MB' % (rel, os.path.getsize(p) / 1048576.0))

    print()
    print('  สร้าง %s' % out)
    print('  ขนาด  %.1f MB' % (os.path.getsize(out) / 1048576.0))
    print('  sha256 %s' % sha256(out))


if __name__ == '__main__':
    main()
