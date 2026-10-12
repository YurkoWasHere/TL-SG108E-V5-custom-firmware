#!/usr/bin/env python3
"""Compare the stock image with the MAC table patch. Offsets include the header."""

from hashlib import sha256
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'original/TL-SG108Ev5.0_en_1.0.0_[20191021-rel.53360]_up.bin'
SOURCE_SHA256 = '65eba08c9270e470dee69331de3e1345c8e5566b7458265fb3d69388b2a1f4db'
TESTED_SHA256 = '5b6b4f4719f52c0d1a4486f162a984db8e78692f555d45be7dadbb28880a9610'

# Reviewed layout of the hardware-tested patch.
REGIONS = [
    ('Outer upgrade header', 0x000000, 20),
    ('Existing handler bank stub', 0x001107, 6),
    ('New common bank stubs', 0x002814, 12),
    ('Embedded upgrade header', 0x004012, 20),
    ('Existing route comparison call', 0x02cf76, 3),
    ('New 8051 routines', 0x035012, 2866),
    ('New route strings and HTML', 0x038012, 4882),
]


def check_container(image):
    header = image[:20]
    payload = bytearray(image[20:])
    if header[:4] != bytes.fromhex('12341085') or header[16:] != bytes.fromhex('332255ff'):
        raise ValueError('Unexpected upgrade header')
    checks = {
        'declared_payload_length_correct': int.from_bytes(header[4:8], 'big') == len(payload),
        'embedded_header_matches': payload[0x3ffe:0x4012] == header,
    }
    payload[0x3ffe:0x4012] = b'\xff' * 20
    header_sum = bytearray(header)
    header_sum[8:12] = bytes(4)
    checks['header_sum_correct'] = sum(header_sum) == int.from_bytes(header[8:12], 'big')
    checks['payload_sum_correct'] = sum(payload) & 0xffffffff == int.from_bytes(header[12:16], 'big')
    if not all(checks.values()):
        raise ValueError(f'Invalid container: {checks}')
    return checks


def compare(original, patched):
    if sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError('Source does not match the reviewed stock image')
    if len(original) != len(patched):
        raise ValueError('Image sizes differ')

    allowed = set()
    rows = []
    for name, start, size in REGIONS:
        before, after = original[start:start + size], patched[start:start + size]
        allowed.update(range(start, start + size))
        row = {
            'name': name,
            'file_start': hex(start),
            'file_end_inclusive': hex(start + size - 1),
            'region_bytes': size,
            'changed_bytes': sum(a != b for a, b in zip(before, after)),
            'original_all_zero': not any(before),
            'original_sha256': sha256(before).hexdigest(),
            'patched_sha256': sha256(after).hexdigest(),
        }
        if size <= 20:
            row.update(original_hex=before.hex(' '), patched_hex=after.hex(' '))
        rows.append(row)

    changed = [i for i, (a, b) in enumerate(zip(original, patched)) if a != b]
    unexpected = [hex(i) for i in changed if i not in allowed]
    if unexpected:
        raise ValueError(f'Changes outside the reviewed regions: {unexpected[:10]}')
    runs = []
    for i in changed:
        if runs and i == runs[-1][1]:
            runs[-1][1] = i + 1
        else:
            runs.append([i, i + 1])

    patched_hash = sha256(patched).hexdigest()
    return {
        'original': SOURCE,
        'patched': 'patch/build/mac-table-experimental.bin',
        'file_size': len(original),
        'original_sha256': SOURCE_SHA256,
        'patched_sha256': patched_hash,
        'matches_hardware_tested_image': patched_hash == TESTED_SHA256,
        'changed_bytes': len(changed),
        'unchanged_bytes': len(original) - len(changed),
        'changed_percent': 100 * len(changed) / len(original),
        'unexpected_changes': unexpected,
        'original_checks': check_container(original),
        'patched_checks': check_container(patched),
        'regions': rows,
        'contiguous_diff_runs': [
            {'start': hex(start), 'end_exclusive': hex(end),
             'original_hex': original[start:end].hex(), 'patched_hex': patched[start:end].hex()}
            for start, end in runs
        ],
    }


def main():
    out = ROOT / 'patch/build'
    report = compare((ROOT / SOURCE).read_bytes(), (out / 'mac-table-experimental.bin').read_bytes())
    (out / 'binary-comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"Comparison: {report['changed_bytes']:,} bytes changed ({report['changed_percent']:.2f}%), no unexpected changes")
    print(f"Matches hardware-tested image: {report['matches_hardware_tested_image']}")


if __name__ == '__main__':
    main()
