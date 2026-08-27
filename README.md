# BLAKE-256

The original SHA-3 finalist, final 14-round variant. **Not BLAKE2 or BLAKE3.**
I kept finding examples of those when I wanted to inspect BLAKE's counter and
padding, so here's a small implementation with those parts left visible.

Only zero salt and whole-byte messages are supported. Python 3.10+, no runtime
dependencies. The streaming interface follows my `sha256` module, but the
final block handling is different — see [the padding notes](docs/algorithm.md).

```python
from blake256 import BLAKE256, hexdigest

assert hexdigest(b"") == (
    "716f6e863f744b9ac22c97ec7b76ea5f"
    "5908bc5b2f67c61510bfc4751384ea7a"
)
h = BLAKE256(b"abc")
h.update(b"")  # must keep the buffered abc
assert h.hexdigest() == hexdigest(b"abc")
```

`BLAKE256` has `update`, `copy`, `digest` and `hexdigest`. Calling `digest`
leaves the object usable; copies can be updated independently. Input can be
bytes, bytearray or memoryview and is consumed immediately. Text isn't accepted.
`update` returns `None`. For older callers, `digest(data)`, `hexdigest(data)`
and the `blake256(data)` constructor are still available.

For files, run `python3 blake256.py file.bin` or pipe binary data into
`python3 blake256.py`. Multiple paths work; `-` reads stdin. Output uses two
spaces between the hex digest and filename. A failed file sets exit status 1
without skipping later files.

`python3 -m pip install .` installs the optional `blake256-py` command.
There is no salt argument, bit-string API or native acceleration.
