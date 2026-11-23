"""32-bit FNV-1a over UTF-16 code units, the same value the JS library computes."""

from prompt_protection._js import code_units

__all__ = ["fnv1a32"]

_FNV_OFFSET = 0x811C9DC5
_FNV_PRIME = 0x01000193
_MASK = 0xFFFFFFFF


def fnv1a32(text: str, seed: int = _FNV_OFFSET) -> int:
    """Hash ``text`` as ``src/utils/hash.ts#fnv1a32`` does. The seed wraps modulo 2**32."""
    h = seed & _MASK
    for unit in code_units(text):
        h = ((h ^ unit) * _FNV_PRIME) & _MASK
    return h
