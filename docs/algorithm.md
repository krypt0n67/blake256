# Implementation notes

This module implements the final 14-round BLAKE-256 proposal. Each round
has four column mixes and four diagonal mixes. Message words are paired with
fixed constants using the ten-row sigma permutation schedule; rounds 10–13
reuse rows 0–3. Word loading and digest serialization are big-endian.

Unlike SHA-256, compression also incorporates a count of message bits processed
so far. Both halves of the 64-bit counter must be XORed into the working state.
Zero-salt mode is the supported API; arbitrary salts and bit-level messages
are deliberately outside its scope.

Finalization has three cases:

- A 55-byte remainder ends with 0x81, followed by the bit length.
- A shorter remainder receives 0x80, zeros, the 0x01 marker and the bit length.
- A 56–63-byte remainder uses two blocks. The second contains only padding,
  so the counter injection must be suppressed.

An empty remainder also requires a padding-only block with a null counter.
An empty update is a no-op: it must not erase an already buffered fragment.
