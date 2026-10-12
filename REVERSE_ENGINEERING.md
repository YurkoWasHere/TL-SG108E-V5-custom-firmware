# Implementation notes

## Hardware result

I flashed the patch on a TL-SG108E 5.0 running
`1.0.0 Build 20191021 Rel.53360`. Screenshots show the updater accepting the
image and the new page completing scans with 30–31 entries, all 65 blocks read.
The MAC table page is not password protected.

SHA-256 of the tested image:
`5b6b4f4719f52c0d1a4486f162a984db8e78692f555d45be7dadbb28880a9610`.

This confirms upload, boot, page serving and table enumeration on one unit.
Front-panel port mapping, session-expiry behavior, VLAN decoding
against known hosts, watchdog timing and sustained load remain unverified.
ASIC port 10 held the switch's own MAC; its role as a CPU port is an inference.

## Image layout

Offsets here refer to the extracted payload. Add `0x14` for upgrade-file offsets.
The image contains banked 8051 code and embedded web assets, with no identified
Linux filesystem. Extraction also recovers 11 GIFs and one PNG.

Common code starts at CPU `0x1000`. Banked code uses CPU `0x4000..0xffff`:

```text
payload_offset = 0x2ffe + (bank - 3) * 0xc000 + (cpu_address - 0x4000)
```

SFR `0x96` selects the bank. Stock helpers `0x1130` and `0x11a8` select banks
7 and 17, saving/restoring the bank through SFR `0xbb`. Generic pointers use
R3:R2:R1: type 1 is XDATA; type `0x81 + bank` is far code.

| Payload offset | Region size | Purpose |
|---|---:|---|
| `0x0010f3` | 6 | Redirect Port Statistics handler |
| `0x002800` | 12 | New comparison stub and original handler stub |
| `0x003ffe` | 20 | Embedded header |
| `0x02cf62` | 3 | Redirect route comparison |
| `0x034ffe` | 2,866 | New code, bank 7:6000 |
| `0x037ffe` | 4,882 | Routes and HTML, bank 7:9000 |

The outer header also changes. Total differing bytes: **7,665**; 7,652 occupy
formerly zero-filled space, five alter existing code, and eight update checksums.
`tools/compare_firmware.py` reproduces the complete comparison.

## Checksums

The 20-byte outer header is duplicated at payload `0x3ffe`. Fields are big-endian:

```text
12341085 0010f340 00000574 03d00ad0 332255ff
magic    length   hdr_sum  data_sum trailer
```

- `hdr_sum`: sum of the other 16 header bytes.
- `data_sum`: sum of payload bytes with the embedded header replaced by twenty
  `0xff` bytes, modulo 2^32.

For stock: `0x03cffcd1 - 0x05ed + 20*255 = 0x03d00ad0`.
The tested patch header is `123410850010f340000005c303dad24d332255ff`.
Both sums reproduce the stock image; the switch accepted the patched image.

## Web handler

Dispatcher bank 6:94b2 uses XDATA `0x2cca` for the client pointer and `0x2ccd`
for the normalized route. Its Port Statistics comparison calls common `0x2baf`
at payload `0x2cf62`, then jumps to common `0x20f3` on a match.

The new comparator recognizes the original path, `/MacTableRpm.htm`, and 65
batch paths. The replacement handler sends the original path through the copied
bank 17:7f75 stub at common `0x3806`. Stock authentication dispatch is unchanged;
its IP checks and `Unauth` routing are around bank 10:90e0..923a.

| Common helper | Bank 7 target | Interface |
|---|---|---|
| `0x1955` | `0x4433` | Initialize response |
| `0x1961` | `0x44fb` | Write HTTP status |
| `0x1967` | `0x469e` | Header pointer at XDATA `0x2e37` |
| `0x196d` | `0x4826` | Raw append: pointer `0x2e68`, 32-bit length `0x2e6b` |
| `0x195b` | `0x4476` | Flush response |

The handler uses the stock 1460-byte send buffer and fixed 40-byte records.
Scratch XDATA `0x2cdf..0x2d1b` reuses the original Port Statistics allocation.
A full analysis of interrupt and downstream-library RAM use is outstanding.

## ASIC table access

The stock LUT getter is bank 5:e0fe. It polls busy bit 13 in `0x0502`, writes
an address to `0x0501`, then writes `(method << 4) | 4` to `0x0500`. After
completion it checks hit bit 12 and reads six words at `0x0520..0x0525`.
Anchors: bank 5:e230 (address), e3b3 (command), e4be (hit), e5dd (data loop).

The patch uses address method 1, command `0x0014`, and slots `0x0000..0x103f`.
It only writes the address and read-command registers. Bus access follows stock
common routines `0x36c7` and `0x374d` through SFRs `0xa0..0xa7`, with bounds of
255 bus polls and 32 LUT polls. IE is saved and interrupts disabled for one
transaction, then restored on success or failure. ASIC learning continues.

The existing `Dump MAC Table` diagnostic is unrelated: bank 11:828c calls bank
5:934a to read 32 saved 16-byte records at flash `0x1ff1e2 + index * 16`.

References: [Realtek RTL8367C LUT API](https://git.openwrt.org/openwrt/openwrt/tree/target/linux/mediatek/files/drivers/net/phy/rtk/rtl8367c/include/rtl8367c_asicdrv_lut.h?h=a2b94afc0df04d82b653509fd88815437fc236ca)
for methods and limits; [Linux Realtek L2 code](https://github.com/torvalds/linux/blob/master/drivers/net/dsa/realtek/rtl8365mb_l2.c)
for record decoding. MAC bytes occupy words 2, 1, 0; word 3 holds VID/IVL and
port extension; word 4 holds age, FID and source port; word 5 bit 5 marks static.

## Data format and tests

`/MacTable00.dat` through `/MacTable40.dat` use lowercase hexadecimal block
numbers. Each returns 64 slots, for 4,160 slots in total. A successful body is
2,570 bytes: `MACT1\n`, 64 records, then `END\n`. A polling failure ends in
`ERR\n`; the browser rejects the incomplete block. Record example:

```text
0000 1000 4455 2233 0011 2001 0b00 0000
```

Fields are requested slot, status register and words 0..5, each four hex digits.
The UI filters for unicast hits with nonzero age or a static flag. Query
parameters are unused; stock route normalization may strip them.

Python tests execute emitted instructions with modeled ASIC, HTTP, strcmp and
bank-switch interfaces. They cover routes, all slots, formatting, original
handler fallback, timeouts, writer errors and IE restoration. Node tests cover
decoding, filtering, full scans and malformed responses. These tests do not
simulate the full firmware, interrupts, TCP stack or physical timing.
