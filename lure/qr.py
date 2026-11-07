"""A small QR code encoder (byte mode, error correction level M, versions 1 to 10).

Standard library only. Writes PNG or SVG. Enough for a bait URL such as
http://10.0.5.20:8080/q/wifi-guest07 printed on a sticky note or a poster.
"""

import struct
import zlib

# Per version (1..10), level M: (total codewords, ec codewords per block, [(blocks, data codewords per block), ...])
_TABLE_M = {
    1: (26, 10, [(1, 16)]), 2: (44, 16, [(1, 28)]), 3: (70, 26, [(1, 44)]), 4: (100, 18, [(2, 32)]),
    5: (134, 24, [(2, 43)]), 6: (172, 16, [(4, 27)]), 7: (196, 18, [(4, 31)]),
    8: (242, 22, [(2, 38), (2, 39)]), 9: (292, 22, [(3, 36), (2, 37)]), 10: (346, 26, [(4, 43), (1, 44)]),
}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38],
          8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}

# Galois field GF(256) with polynomial 0x11d.
_EXP, _LOG = [0] * 512, [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gmul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _rs_ec(data, n):
    gen = [1]
    for i in range(n):
        nxt = [0] * (len(gen) + 1)
        for j, g in enumerate(gen):
            nxt[j] ^= g
            nxt[j + 1] ^= _gmul(g, _EXP[i])
        gen = nxt
    rem = list(data) + [0] * n
    for i in range(len(data)):
        c = rem[i]
        if c:
            for j in range(1, len(gen)):
                rem[i + j] ^= _gmul(gen[j], c)
    return rem[len(data):]


def _bits(data, version):
    total_data = sum(b * d for b, d in _TABLE_M[version][2])
    count_bits = 8 if version < 10 else 16
    bits = [0, 1, 0, 0] + [int(c) for c in format(len(data), f"0{count_bits}b")]
    for byte in data:
        bits += [int(c) for c in format(byte, "08b")]
    cap = total_data * 8
    bits += [0] * min(4, cap - len(bits))
    bits += [0] * (-len(bits) % 8)
    codes = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(codes) < total_data:
        codes.append(pad)
        pad = 0x11 if pad == 0xEC else 0xEC
    return codes


def _interleave(codes, version):
    _, ec_n, groups = _TABLE_M[version]
    blocks, pos = [], 0
    for count, size in groups:
        for _ in range(count):
            blocks.append(codes[pos:pos + size])
            pos += size
    ecs = [_rs_ec(b, ec_n) for b in blocks]
    out = []
    for i in range(max(len(b) for b in blocks)):
        out += [b[i] for b in blocks if i < len(b)]
    for i in range(ec_n):
        out += [e[i] for e in ecs]
    return out


def _format_bits(mask):
    data = (0 << 3) | mask  # level M has format bits 00
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return ((data << 10) | rem) ^ 0x5412


def _version_bits(version):
    rem = version
    for _ in range(12):
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
    return (version << 12) | rem


_MASKS = [
    lambda r, c: (r + c) % 2 == 0, lambda r, c: r % 2 == 0, lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0, lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0, lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
]


def _place(version, codewords, mask):
    n = 17 + 4 * version
    m = [[None] * n for _ in range(n)]

    def finder(r, c):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                rr, cc = r + dr, c + dc
                if 0 <= rr < n and 0 <= cc < n:
                    on = (0 <= dr <= 6 and dc in (0, 6)) or (0 <= dc <= 6 and dr in (0, 6)) or (2 <= dr <= 4 and 2 <= dc <= 4)
                    m[rr][cc] = on
    finder(0, 0), finder(0, n - 7), finder(n - 7, 0)
    for i in range(8, n - 8):
        m[6][i] = m[i][6] = i % 2 == 0
    pos = _ALIGN[version]
    last = len(pos) - 1
    for i, r in enumerate(pos):
        for j, c in enumerate(pos):
            if (i, j) in ((0, 0), (0, last), (last, 0)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    m[r + dr][c + dc] = max(abs(dr), abs(dc)) != 1
    m[n - 8][8] = True  # dark module
    reserved = [[v is not None for v in row] for row in m]
    for i in range(9):
        reserved[8][i] = reserved[i][8] = True
    for i in range(8):
        reserved[8][n - 1 - i] = reserved[n - 1 - i][8] = True
    if version >= 7:
        for i in range(6):
            for j in range(3):
                reserved[i][n - 11 + j] = reserved[n - 11 + j][i] = True
    bits = []
    for cw in codewords:
        bits += [(cw >> (7 - i)) & 1 for i in range(8)]
    idx, up, col = 0, True, n - 1
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(n - 1, -1, -1) if up else range(n)
        for r in rows:
            for c in (col, col - 1):
                if not reserved[r][c]:
                    bit = bits[idx] if idx < len(bits) else 0
                    idx += 1
                    m[r][c] = bool(bit) ^ _MASKS[mask](r, c)
        up = not up
        col -= 2
    fb = _format_bits(mask)
    bit = lambda i: bool((fb >> i) & 1)
    for i in range(6):
        m[i][8] = bit(i)
    m[7][8] = bit(6)
    m[8][8] = bit(7)
    m[8][7] = bit(8)
    for i in range(9, 15):
        m[8][14 - i] = bit(i)
    for i in range(8):
        m[8][n - 1 - i] = bit(i)
    for i in range(8, 15):
        m[n - 15 + i][8] = bit(i)
    m[n - 8][8] = True
    if version >= 7:
        vb = _version_bits(version)
        for i in range(18):
            bit = bool((vb >> i) & 1)
            m[i // 3][n - 11 + i % 3] = bit
            m[n - 11 + i % 3][i // 3] = bit
    return m


def _penalty(m):
    n, score = len(m), 0
    for grid in (m, list(zip(*m))):
        for row in grid:
            run, prev = 0, None
            for v in row:
                if v == prev:
                    run += 1
                else:
                    if run >= 5:
                        score += run - 2
                    run, prev = 1, v
            if run >= 5:
                score += run - 2
    for r in range(n - 1):
        for c in range(n - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                score += 3
    dark = sum(v for row in m for v in row)
    score += abs(dark * 20 // (n * n) - 10) * 10
    return score


def encode(text):
    """Return the QR matrix (list of rows of booleans) for text."""
    data = text.encode("utf-8")
    for version in range(1, 11):
        cap = sum(b * d for b, d in _TABLE_M[version][2]) - (2 if version < 10 else 3)
        if len(data) <= cap:
            break
    else:
        raise ValueError("text too long for a version 10 QR code")
    codewords = _interleave(_bits(data, version), version)
    return min((_place(version, codewords, k) for k in range(8)), key=_penalty)


def to_png(matrix, path, scale=10, border=4):
    n = len(matrix)
    size = (n + 2 * border) * scale
    rows = []
    for y in range(size):
        r = y // scale - border
        line = bytearray([0])
        for x in range(size):
            c = x // scale - border
            dark = 0 <= r < n and 0 <= c < n and matrix[r][c]
            line.append(0 if dark else 255)
        rows.append(bytes(line))
    raw = b"".join(rows)

    def chunk(tag, body):
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 0, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def to_svg(matrix, path, border=4):
    n = len(matrix) + 2 * border
    rects = "".join(f'<rect x="{c + border}" y="{r + border}" width="1" height="1"/>'
                    for r, row in enumerate(matrix) for c, v in enumerate(row) if v)
    with open(path, "w") as f:
        f.write(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" shape-rendering="crispEdges">'
                f'<rect width="{n}" height="{n}" fill="#fff"/><g fill="#000">{rects}</g></svg>')
