#!/usr/bin/env python3
"""Extract the TL-SG108E v5 upgrade wrapper and embedded web images."""

from hashlib import sha256
from pathlib import Path
import argparse
import json
import struct


SOURCE = Path('original/TL-SG108Ev5.0_en_1.0.0_[20191021-rel.53360]_up.bin')
OUT = Path('unpacked')


def gif_end(data, start):
    pos = start + 13
    packed = data[start + 10]
    if packed & 0x80:
        pos += 3 * (1 << ((packed & 7) + 1))
    while pos < len(data):
        marker = data[pos]
        pos += 1
        if marker == 0x3B:
            return pos
        if marker == 0x2C:
            if pos + 9 > len(data):
                return None
            packed = data[pos + 8]
            pos += 9
            if packed & 0x80:
                pos += 3 * (1 << ((packed & 7) + 1))
            pos += 1  # LZW minimum code size
        elif marker == 0x21:
            pos += 1  # extension type
        else:
            return None
        while pos < len(data):
            size = data[pos]
            pos += 1
            if size == 0:
                break
            pos += size
    return None


def png_end(data, start):
    pos = start + 8
    while pos + 12 <= len(data):
        size = struct.unpack_from('>I', data, pos)[0]
        kind = data[pos + 4:pos + 8]
        if size > len(data) - pos - 12:
            return None
        pos += 12 + size
        if kind == b'IEND':
            return pos
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--quiet', action='store_true', help='Write files without printing the manifest')
    args = parser.parse_args()
    data = SOURCE.read_bytes()
    declared = struct.unpack_from('>I', data, 4)[0]
    header_size = len(data) - declared
    if data[:4] != bytes.fromhex('12341085') or header_size != 20:
        raise ValueError('Unexpected firmware header or payload length')
    OUT.mkdir(exist_ok=True)
    (OUT / 'upgrade_header.bin').write_bytes(data[:header_size])
    (OUT / 'firmware_payload.bin').write_bytes(data[header_size:])

    assets = []
    for kind, signature, ending, suffix in [
        ('GIF', b'GIF89a', gif_end, 'gif'),
        ('PNG', b'\x89PNG\r\n\x1a\n', png_end, 'png'),
    ]:
        pos = 0
        while (pos := data.find(signature, pos)) != -1:
            end = ending(data, pos)
            if end is not None:
                name = f'{kind.lower()}_{pos:06x}.{suffix}'
                dest = OUT / 'web_images' / name
                dest.parent.mkdir(exist_ok=True)
                dest.write_bytes(data[pos:end])
                assets.append({'file': str(dest), 'offset': pos, 'size': end - pos})
            pos += len(signature)

    manifest = {
        'source': str(SOURCE),
        'source_sha256': sha256(data).hexdigest(),
        'source_size': len(data),
        'header_size': header_size,
        'header_hex': data[:header_size].hex(),
        'payload_size': declared,
        'payload_sha256': sha256(data[header_size:]).hexdigest(),
        'images': assets,
    }
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    if not args.quiet:
        print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
