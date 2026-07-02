# BLAKE-256 notes

Trying the original 14-round BLAKE, with zero salt. The bit counter and final
block rules are the parts I want to get straight.

Short-message compression is in place. This is not BLAKE2.

Full blocks work; still sorting out the final counter cases.
