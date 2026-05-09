"""
Reed-Solomon Error Correction over GF(2^8)
Primitive polynomial: 0x11d (x^8 + x^4 + x^3 + x^2 + 1)
Generator element: alpha = 0x02
Field characteristic: 255

Implements full RS codec for SiliconSignature cross-platform compatibility.
Uses the proven `reedsolo` library algorithm with matching parameters:
- fcr=0 (first consecutive root = alpha^0)
- prim=0x11d (primitive polynomial)
- generator=2 (primitive element alpha)

Polynomials are stored HIGHEST-degree-first (index 0 = leading coefficient),
matching the reedsolo reference convention.

API:
    rs_encode_msg(data, nsym=32) -> codeword (data + ecc)
    rs_decode_msg(codeword, nsym=32) -> data or None
"""

import array
import importlib

# ---------------------------------------------------------------------------
# GF(2^8) tables
# ---------------------------------------------------------------------------

RS_PRIM = 0x11d
FIELD_CHARAC = 255

GF_EXP = array.array('H', [0] * 512)
GF_LOG = array.array('B', [0] * 256)


def _init_tables():
    x = 1
    for i in range(255):
        GF_EXP[i] = x
        GF_EXP[i + 255] = x
        GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= RS_PRIM
    GF_EXP[510] = GF_EXP[0]
    GF_EXP[511] = GF_EXP[1]


_init_tables()

# ---------------------------------------------------------------------------
# GF(2^8) Arithmetic
# ---------------------------------------------------------------------------


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return GF_EXP[GF_LOG[a] + GF_LOG[b]]


def gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF")
    if a == 0:
        return 0
    return GF_EXP[(GF_LOG[a] - GF_LOG[b] + 255) % 255]


def gf_pow(a: int, n: int) -> int:
    if n == 0:
        return 1
    if a == 0:
        return 0
    return GF_EXP[(GF_LOG[a] * n) % 255]


def gf_inverse(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("Inverse of zero")
    return GF_EXP[-GF_LOG[a] % 255]


def gf_sub(a: int, b: int) -> int:
    return a ^ b


# ---------------------------------------------------------------------------
# Polynomial Operations (highest-degree-first convention)
# ---------------------------------------------------------------------------


def gf_poly_mul(a, b):
    """Multiply two polynomials (highest-degree-first)."""
    result = [0] * (len(a) + len(b) - 1)
    for i in range(len(a)):
        if a[i] == 0:
            continue
        for j in range(len(b)):
            if b[j] == 0:
                continue
            result[i + j] ^= gf_mul(a[i], b[j])
    return result


def gf_poly_eval(poly, x):
    """Evaluate polynomial at x (highest-degree-first)."""
    result = 0
    for coef in poly:
        result = gf_mul(result, x) ^ coef
    return result


# ---------------------------------------------------------------------------
# Reed-Solomon Encoding
# ---------------------------------------------------------------------------


def _rs_generator_poly(nsym):
    """Generate RS generator polynomial (highest-degree-first)."""
    g = [1]
    for i in range(nsym):
        g = gf_poly_mul(g, [1, gf_pow(2, i)])
    return g


def rs_encode_msg(data: bytes, nsym: int = 32) -> bytes:
    """RS encode: append ECC parity bytes using synthetic division.

    Args:
        data: Input data bytes
        nsym: Number of ECC symbols (default 32)

    Returns:
        Codeword (data + ECC) as bytes
    """
    gen = _rs_generator_poly(nsym)
    msg_out = bytearray(data) + bytearray(nsym)

    for i in range(len(data)):
        coef = msg_out[i]
        if coef != 0:
            lcoef = GF_LOG[coef]
            for j in range(1, len(gen)):
                msg_out[i + j] ^= GF_EXP[(lcoef + GF_LOG[gen[j]]) % 255]

    msg_out[:len(data)] = data
    return bytes(msg_out)


# ---------------------------------------------------------------------------
# Reed-Solomon Decoding
# ---------------------------------------------------------------------------
# The decoder uses the proven reedsolo library for reliability.
# We sync our GF tables with reedsolo's globals before each decode call.


def _sync_reedsolo_globals():
    """Synchronize our GF tables with the reedsolo library."""
    try:
        rs = importlib.import_module('reedsolo')
        # Only sync if tables differ
        if rs.gf_exp[1] != GF_EXP[1]:
            rs.gf_exp = list(GF_EXP)
            rs.gf_log = list(GF_LOG)
            rs.field_charac = FIELD_CHARAC
    except ImportError:
        pass


def rs_decode_msg(data: bytes, nsym: int = 32):
    """RS decode with error correction.

    Args:
        data: Received codeword (data + ECC)
        nsym: Number of ECC symbols (default 32)

    Returns:
        Corrected data (without ECC) or None if uncorrectable
    """
    if len(data) <= nsym:
        return None

    try:
        import reedsolo as rs
        _sync_reedsolo_globals()

        result = rs.rs_correct_msg(data, nsym, fcr=0, generator=2)
        return bytes(result[0])

    except ImportError:
        # Fallback to naive decode without error correction
        # This handles the no-error case
        from reedsolomon import gf_poly_eval, gf_pow

        # Quick syndrome check
        has_error = False
        for i in range(nsym):
            s = gf_poly_eval(data, gf_pow(2, i))
            if s != 0:
                has_error = True
                break

        if not has_error:
            return data[:-nsym]
        return None

    except Exception:
        return None


# Backward-compatible aliases
rs_encode = rs_encode_msg
rs_decode = rs_decode_msg
