"""
NullSec LoRa Mesh - Reed-Solomon Forward Error Correction

Adds redundancy to LoRa frames for reliable delivery
over noisy RF channels.
"""

import struct
from typing import Optional


# GF(256) primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1
GF_PRIMITIVE = 0x11D
GF_SIZE = 256

# Pre-computed tables
_gf_exp = [0] * 512
_gf_log = [0] * 256
_tables_initialized = False


def _init_tables():
    """Initialize Galois Field lookup tables."""
    global _tables_initialized
    if _tables_initialized:
        return

    x = 1
    for i in range(255):
        _gf_exp[i] = x
        _gf_log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= GF_PRIMITIVE

    for i in range(255, 512):
        _gf_exp[i] = _gf_exp[i - 255]

    _tables_initialized = True


def _gf_mul(a: int, b: int) -> int:
    """Multiply in GF(256)."""
    if a == 0 or b == 0:
        return 0
    return _gf_exp[(_gf_log[a] + _gf_log[b]) % 255]


def _gf_div(a: int, b: int) -> int:
    """Divide in GF(256)."""
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(256)")
    if a == 0:
        return 0
    return _gf_exp[(_gf_log[a] - _gf_log[b]) % 255]


def _gf_poly_mul(p: list, q: list) -> list:
    """Multiply two polynomials in GF(256)."""
    result = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        for j, b in enumerate(q):
            result[i + j] ^= _gf_mul(a, b)
    return result


def _gf_poly_eval(poly: list, x: int) -> int:
    """Evaluate polynomial at x in GF(256)."""
    result = poly[0]
    for i in range(1, len(poly)):
        result = _gf_mul(result, x) ^ poly[i]
    return result


class ReedSolomon:
    """
    Reed-Solomon forward error correction encoder/decoder.

    Designed for LoRa frame sizes (up to 255 bytes total).
    Default: RS(255, 223) — 32 parity bytes, can correct up to 16 errors.

    For LoRa mesh, typical settings:
    - RS(255, 239) = 16 parity bytes, correct 8 errors (light FEC)
    - RS(255, 223) = 32 parity bytes, correct 16 errors (standard)
    - RS(255, 191) = 64 parity bytes, correct 32 errors (heavy FEC)
    """

    def __init__(self, nsym: int = 16):
        """
        Initialize Reed-Solomon codec.

        Args:
            nsym: Number of parity symbols (error correction capacity = nsym/2)
        """
        _init_tables()
        self.nsym = nsym
        self.generator = self._build_generator(nsym)

    def encode(self, data: bytes) -> bytes:
        """
        Encode data with Reed-Solomon parity.

        Returns data + parity bytes appended.
        """
        if len(data) + self.nsym > 255:
            raise ValueError(
                f"Data too large for RS: {len(data)} + {self.nsym} > 255"
            )

        # Convert to list for GF operations
        msg = list(data) + [0] * self.nsym

        for i in range(len(data)):
            coef = msg[i]
            if coef != 0:
                for j in range(len(self.generator)):
                    msg[i + j] ^= _gf_mul(self.generator[j], coef)

        # Return original data + computed parity
        return bytes(list(data) + msg[len(data):])

    def decode(self, data: bytes) -> Optional[bytes]:
        """
        Decode and error-correct RS-encoded data.

        Returns corrected data (without parity) or None if uncorrectable.
        """
        msg = list(data)

        # Calculate syndromes
        syndromes = [_gf_poly_eval(msg, _gf_exp[i]) for i in range(self.nsym)]

        if all(s == 0 for s in syndromes):
            # No errors
            return bytes(msg[:-self.nsym])

        # Berlekamp-Massey to find error locator polynomial
        err_loc = self._berlekamp_massey(syndromes)
        if err_loc is None:
            return None  # Uncorrectable

        # Find error positions using Chien search
        err_pos = self._chien_search(err_loc, len(msg))
        if err_pos is None or len(err_pos) > self.nsym // 2:
            return None  # Too many errors

        # Forney algorithm to find error values
        err_val = self._forney(syndromes, err_loc, err_pos, len(msg))
        if err_val is None:
            return None

        # Correct errors
        for pos, val in zip(err_pos, err_val):
            msg[pos] ^= val

        return bytes(msg[:-self.nsym])

    @property
    def max_corrections(self) -> int:
        """Maximum number of errors that can be corrected."""
        return self.nsym // 2

    @property
    def overhead_bytes(self) -> int:
        """Number of parity bytes added."""
        return self.nsym

    def _build_generator(self, nsym: int) -> list:
        """Build generator polynomial."""
        g = [1]
        for i in range(nsym):
            g = _gf_poly_mul(g, [1, _gf_exp[i]])
        return g

    def _berlekamp_massey(self, syndromes: list) -> Optional[list]:
        """Berlekamp-Massey algorithm for error locator polynomial."""
        n = len(syndromes)
        C = [1] + [0] * n
        B = [1] + [0] * n
        L = 0
        m = 1
        b = 1

        for i in range(n):
            d = syndromes[i]
            for j in range(1, L + 1):
                d ^= _gf_mul(C[j], syndromes[i - j])

            if d == 0:
                m += 1
            elif 2 * L <= i:
                T = C[:]
                coef = _gf_div(d, b)
                for j in range(m, n + 1):
                    C[j] ^= _gf_mul(coef, B[j - m])
                L = i + 1 - L
                B = T
                b = d
                m = 1
            else:
                coef = _gf_div(d, b)
                for j in range(m, n + 1):
                    C[j] ^= _gf_mul(coef, B[j - m])
                m += 1

        return C[:L + 1] if L <= self.nsym // 2 else None

    def _chien_search(self, err_loc: list, n: int) -> Optional[list]:
        """Find error positions using Chien search."""
        errs = []
        for i in range(n):
            val = _gf_poly_eval(err_loc, _gf_exp[255 - i])
            if val == 0:
                errs.append(i)

        return errs if len(errs) == len(err_loc) - 1 else None

    def _forney(self, syndromes: list, err_loc: list,
                err_pos: list, n: int) -> Optional[list]:
        """Forney algorithm to compute error magnitudes."""
        # Compute error evaluator polynomial
        omega = _gf_poly_mul(syndromes + [1], err_loc)
        omega = omega[:len(err_loc)]

        values = []
        for pos in err_pos:
            xi_inv = _gf_exp[255 - (255 - pos)]

            # Error locator derivative
            err_loc_prime = 0
            for j in range(1, len(err_loc), 2):
                err_loc_prime ^= _gf_mul(err_loc[j], _gf_exp[(255 - pos) * (j - 1) % 255])

            if err_loc_prime == 0:
                return None

            omega_val = _gf_poly_eval(omega, xi_inv)
            values.append(_gf_div(omega_val, err_loc_prime))

        return values
