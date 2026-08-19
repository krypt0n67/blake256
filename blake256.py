"""Original BLAKE-256 (14 rounds), byte-aligned input and zero salt.

This implements the SHA-3 finalist, not BLAKE2s or BLAKE3. Compression and
finalization are written in Python; there is no native hash dependency.
"""

import struct

_MASK = 0xFFFFFFFF
_IV = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)
_C = (
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
    0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
)
_SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)


def _ror(word, shift):
    return ((word >> shift) | (word << (32 - shift))) & _MASK


def _mix(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & _MASK
    v[d] = _ror(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & _MASK
    v[b] = _ror(v[b] ^ v[c], 12)
    v[a] = (v[a] + v[b] + y) & _MASK
    v[d] = _ror(v[d] ^ v[a], 8)
    v[c] = (v[c] + v[d]) & _MASK
    v[b] = _ror(v[b] ^ v[c], 7)


def _compress(state, block, counter, null_counter=False):
    words = struct.unpack('>16I', block)
    # The four salt words are zero in this byte-oriented implementation.
    v = list(state) + list(_C[:8])
    if not null_counter:
        low, high = counter & _MASK, (counter >> 32) & _MASK
        v[12] ^= low
        v[13] ^= low
        v[14] ^= high
        v[15] ^= high
    lanes = (
        (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
        (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14),
    )
    for round_number in range(14):
        permutation = _SIGMA[round_number % 10]
        for pair, lane in enumerate(lanes):
            x, y = permutation[2 * pair:2 * pair + 2]
            _mix(v, *lane, words[x] ^ _C[y], words[y] ^ _C[x])
    return [state[i] ^ v[i] ^ v[i + 8] for i in range(8)]


class BLAKE256:
    """Incremental original BLAKE-256 with non-destructive digest snapshots."""

    name = 'blake256'
    block_size = 64
    digest_size = 32

    def __init__(self, data=b''):
        self._state = list(_IV)
        self._buffer = b''
        self._count = 0
        self.update(data)

    def update(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data must be bytes, bytearray or memoryview')
        data = bytes(data)
        if self._count + len(data) >= 1 << 61:
            raise OverflowError('BLAKE-256 messages must be shorter than 2**64 bits')
        processed = self._count - len(self._buffer)
        self._count += len(data)
        data = self._buffer + data
        end = len(data) - len(data) % self.block_size
        for offset in range(0, end, self.block_size):
            counter = (processed + offset + self.block_size) * 8
            self._state = _compress(self._state, data[offset:offset + 64], counter)
        self._buffer = data[end:]

    def copy(self):
        clone = object.__new__(type(self))
        clone._state = self._state.copy()
        clone._buffer = self._buffer
        clone._count = self._count
        return clone

    def digest(self):
        state = self._state.copy()
        counter = self._count * 8
        size = len(self._buffer)
        length = struct.pack('>Q', counter)
        if size == 55:
            # The initial padding bit and the 256-bit domain marker share a byte.
            tail = self._buffer + b'\x81' + length
            state = _compress(state, tail, counter)
        elif size < 55:
            tail = self._buffer + b'\x80' + b'\x00' * (54 - size) + b'\x01' + length
            state = _compress(state, tail, counter, null_counter=(size == 0))
        else:
            tail = self._buffer + b'\x80' + b'\x00' * (63 - size)
            state = _compress(state, tail, counter)
            # This second block contains no message bits: suppress the counter.
            tail = b'\x00' * 55 + b'\x01' + length
            state = _compress(state, tail, counter, null_counter=True)
        return struct.pack('>8I', *state)

    def hexdigest(self):
        return self.digest().hex()


def blake256(data=b''):
    return BLAKE256(data)


def digest(data):
    """One-shot byte digest, retained from the original API."""
    return BLAKE256(data).digest()


def hexdigest(data):
    return digest(data).hex()


def main(argv=None):
    """Print checksums for binary files, or stdin when no file is given."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('files', nargs='*', help='Files to hash; - reads stdin')
    args = parser.parse_args(argv)
    failed = False
    for filename in args.files or ['-']:
        try:
            value = BLAKE256()
            if filename == '-':
                for chunk in iter(lambda: sys.stdin.buffer.read(65536), b''):
                    value.update(chunk)
            else:
                with open(filename, 'rb') as stream:
                    for chunk in iter(lambda: stream.read(65536), b''):
                        value.update(chunk)
            print(f'{value.hexdigest()}  {filename}')
        except OSError as error:
            print(f'blake256: {filename}: {error.strerror}', file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
