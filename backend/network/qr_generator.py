"""Pure Python QR Code Generator (Model 2, Version 1-4, Byte Mode).

Generates standalone SVG QR codes with zero external dependencies,
allowing phones and attendees to scan and open the local or public joining URL.
"""
from __future__ import annotations

import math
from typing import List, Tuple

# Galois Field GF(256) tables for Reed-Solomon computation
GF_EXP = [0] * 512
GF_LOG = [0] * 256

def _init_gf():
    x = 1
    for i in range(255):
        GF_EXP[i] = x
        GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        GF_EXP[i] = GF_EXP[i - 255]

_init_gf()

def _gf_mul(x: int, y: int) -> int:
    if x == 0 or y == 0:
        return 0
    return GF_EXP[GF_LOG[x] + GF_LOG[y]]

def _rs_poly(ec_len: int) -> List[int]:
    """Computes Reed-Solomon generator polynomial for given error correction length."""
    poly = [1]
    for i in range(ec_len):
        next_poly = [0] * (len(poly) + 1)
        for j, c in enumerate(poly):
            next_poly[j] ^= _gf_mul(c, GF_EXP[i])
            next_poly[j + 1] ^= c
        poly = next_poly
    return poly

def _rs_encode(data: List[int], ec_len: int) -> List[int]:
    """Generates Reed-Solomon error correction codewords."""
    poly = _rs_poly(ec_len)
    msg = data + [0] * ec_len
    for i in range(len(data)):
        lead = msg[i]
        if lead != 0:
            for j in range(len(poly)):
                msg[i + j] ^= _gf_mul(poly[j], lead)
    return msg[len(data):]

# QR Version Specifications for Error Correction Level L
# (Version, total_data_codewords, ec_codewords, total_codewords, dimension, alignment_pos)
QR_SPECS_L = [
    (1, 19, 7, 26, 21, []),
    (2, 34, 10, 44, 25, [6, 18]),
    (3, 55, 15, 70, 29, [6, 22]),
    (4, 80, 20, 100, 33, [6, 26]),
    (5, 108, 26, 134, 37, [6, 30]),
    (6, 136, 36, 172, 41, [6, 34]),
]

# Format info for Level L, Mask 0 (001011010001001)
FORMAT_INFO_L_MASK0 = 0x77C4


def _encode_data(text: str, data_cap: int) -> List[int]:
    """Encodes ASCII/UTF-8 string into byte-mode QR data codewords."""
    raw = text.encode("utf-8")
    length = len(raw)

    # 4 bits mode (0100 = Byte Mode) + 8 bits character count
    bits = "0100" + f"{length:08b}"
    for b in raw:
        bits += f"{b:08b}"

    # Terminator up to 4 bits
    req_bits = data_cap * 8
    pad_needed = min(4, req_bits - len(bits))
    bits += "0" * max(0, pad_needed)

    # Align to full byte
    if len(bits) % 8 != 0:
        bits += "0" * (8 - (len(bits) % 8))

    codewords = [int(bits[i:i+8], 2) for i in range(0, len(bits), 8)]

    # Pad codewords alternating 0xEC and 0x11
    pad_bytes = [0xEC, 0x11]
    pad_idx = 0
    while len(codewords) < data_cap:
        codewords.append(pad_bytes[pad_idx % 2])
        pad_idx += 1

    return codewords


def _build_matrix(version: int, data_codewords: List[int], ec_codewords: List[int]) -> List[List[int]]:
    """Builds the 2D QR matrix with finder patterns, timing, alignment, data and mask."""
    dim = 21 + (version - 1) * 4
    matrix = [[None] * dim for _ in range(dim)]
    reserved = [[False] * dim for _ in range(dim)]

    def set_module(r, c, val):
        matrix[r][c] = val
        reserved[r][c] = True

    # 1. Finder patterns (7x7) + separators at (0,0), (0, dim-7), (dim-7, 0)
    def place_finder(r_start, c_start):
        for r in range(7):
            for c in range(7):
                if r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4):
                    set_module(r_start + r, c_start + c, 1)
                else:
                    set_module(r_start + r, c_start + c, 0)

        # Separator borders
        for r in range(-1, 8):
            for c in range(-1, 8):
                pr, pc = r_start + r, c_start + c
                if 0 <= pr < dim and 0 <= pc < dim and not reserved[pr][pc]:
                    set_module(pr, pc, 0)

    place_finder(0, 0)
    place_finder(0, dim - 7)
    place_finder(dim - 7, 0)

    # 2. Timing patterns (row 6 and col 6)
    for i in range(8, dim - 8):
        val = 1 if i % 2 == 0 else 0
        if not reserved[6][i]:
            set_module(6, i, val)
        if not reserved[i][6]:
            set_module(i, 6, val)

    # 3. Alignment patterns (version >= 2)
    spec = next(s for s in QR_SPECS_L if s[0] == version)
    align_coords = spec[5]
    if align_coords:
        for r_center in align_coords:
            for c_center in align_coords:
                # Skip if overlapping with finder patterns
                if (r_center <= 8 and c_center <= 8) or \
                   (r_center <= 8 and c_center >= dim - 8) or \
                   (r_center >= dim - 8 and c_center <= 8):
                    continue
                for dr in range(-2, 3):
                    for dc in range(-2, 3):
                        val = 1 if (abs(dr) == 2 or abs(dc) == 2 or (dr == 0 and dc == 0)) else 0
                        set_module(r_center + dr, c_center + dc, val)

    # 4. Dark module
    set_module(4 * version + 9, 8, 1)

    # 5. Reserve Format information areas
    for c in range(9):
        if not reserved[8][c]: reserved[8][c] = True
    for r in range(9):
        if not reserved[r][8]: reserved[r][8] = True
    for c in range(dim - 8, dim):
        reserved[8][c] = True
    for r in range(dim - 7, dim):
        reserved[r][8] = True

    # 6. Zig-zag data placement
    all_codewords = data_codewords + ec_codewords
    bit_stream = "".join(f"{b:08b}" for b in all_codewords)
    bit_idx = 0
    total_bits = len(bit_stream)

    c = dim - 1
    going_up = True
    while c > 0:
        if c == 6:  # Skip vertical timing pattern column
            c -= 1
        cols = [c, c - 1]
        rows = range(dim - 1, -1, -1) if going_up else range(dim)
        for r in rows:
            for col in cols:
                if not reserved[r][col]:
                    val = int(bit_stream[bit_idx]) if bit_idx < total_bits else 0
                    bit_idx += 1
                    # Apply Mask 0: (r + col) % 2 == 0
                    if (r + col) % 2 == 0:
                        val ^= 1
                    matrix[r][col] = val
        going_up = not going_up
        c -= 2

    # 7. Write Format information (Level L, Mask 0)
    fmt = FORMAT_INFO_L_MASK0
    fmt_bits = [ (fmt >> i) & 1 for i in range(15) ]

    # Horizontal format area
    idx = 0
    for col in range(9):
        if col != 6:
            matrix[8][col] = fmt_bits[idx]
            idx += 1
    matrix[8][7] = fmt_bits[6]
    matrix[8][8] = fmt_bits[7]
    matrix[7][8] = fmt_bits[8]
    idx = 9
    for r in range(5, -1, -1):
        if r != 6:
            matrix[r][8] = fmt_bits[idx]
            idx += 1

    # Second copy around other finder patterns
    for i in range(8):
        matrix[dim - 1 - i][8] = fmt_bits[i]
    for i in range(7):
        matrix[8][dim - 7 + i] = fmt_bits[8 + i]

    return [[1 if cell == 1 else 0 for cell in row] for row in matrix]


def generate_qr_matrix(text: str) -> List[List[int]]:
    """Encodes text into a 2D QR Code binary matrix (1 for black, 0 for white)."""
    text_len = len(text.encode("utf-8"))
    chosen_spec = None
    for spec in QR_SPECS_L:
        # Byte mode overhead: 4 bits mode + 8 bits length = 12 bits (1.5 bytes)
        max_bytes = spec[1] - 2
        if text_len <= max_bytes:
            chosen_spec = spec
            break

    if not chosen_spec:
        # Fallback to largest supported version
        chosen_spec = QR_SPECS_L[-1]

    version, data_cap, ec_len, _, _, _ = chosen_spec
    data_codewords = _encode_data(text, data_cap)
    ec_codewords = _rs_encode(data_codewords, ec_len)
    return _build_matrix(version, data_codewords, ec_codewords)


def generate_qr_svg(text: str, size: int = 240, border: int = 4, bg_color: str = "#ffffff", fg_color: str = "#0f172a") -> str:
    """Renders a URL into a standalone, phone-scannable SVG QR code string."""
    matrix = generate_qr_matrix(text)
    dim = len(matrix)
    total_dim = dim + border * 2
    viewbox = f"0 0 {total_dim} {total_dim}"

    rects = []
    for r in range(dim):
        for c in range(dim):
            if matrix[r][c] == 1:
                rects.append(f'<rect x="{c + border}" y="{r + border}" width="1" height="1" fill="{fg_color}"/>')

    rects_str = "".join(rects)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{viewbox}" width="{size}" height="{size}" '
        f'shape-rendering="crispEdges" aria-label="Join QR Code">'
        f'<rect width="100%" height="100%" fill="{bg_color}"/>'
        f'{rects_str}'
        f'</svg>'
    )

