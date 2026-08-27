# BLAKE-256 changes

## v0.2.0 / 2026-08-27

- Streaming state and copies, keeping the one-shot functions available.
- Empty updates no longer drop an unfinished block.
- Inject both halves of the bit counter. The high word was being lost.
- Buffer type checks and a file checksum command (`blake256-py` when installed).

## v0.1.0 / 2026-07-07

- Compression with all 14 rounds.
- The 55-byte tail uses the combined `0x81` marker.
- Long tails get a second final block, with counter injection disabled for
  that padding-only block.
