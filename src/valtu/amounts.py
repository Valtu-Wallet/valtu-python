"""Amounts travel as integer strings in base units. These convert to and from
decimal strings exactly (no floating point)."""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Union

_AMOUNT = re.compile(r"^(\d*)(?:\.(\d*))?$")


def to_base_units(value: Union[str, int, Decimal], decimals: int) -> str:
    """``"25.5"`` with 6 decimals → ``"25500000"``. Raises ValueError on more decimals than the asset has.

    Floats are refused: pass a string or Decimal so 0.1 stays 0.1.
    """
    if isinstance(value, float):
        raise TypeError("pass the amount as a string or Decimal, not a float")
    s = format(value, "f") if isinstance(value, Decimal) else str(value).strip()
    m = _AMOUNT.match(s)
    if not m or (m.group(1) == "" and not m.group(2)):
        raise ValueError(f'not a positive decimal amount: "{value}"')
    whole = m.group(1) or "0"
    frac = (m.group(2) or "").rstrip("0")
    if len(frac) > decimals:
        raise ValueError(f'"{value}" has more than {decimals} decimals')
    return str(int(whole) * 10**decimals + int(frac.ljust(decimals, "0") or "0"))


def from_base_units(amount: Union[str, int], decimals: int) -> str:
    """``"25500000"`` with 6 decimals → ``"25.5"``."""
    v = int(amount)
    neg = v < 0
    v = -v if neg else v
    unit = 10**decimals
    frac = str(v % unit).rjust(decimals, "0").rstrip("0") if decimals else ""
    return f"{'-' if neg else ''}{v // unit}{'.' + frac if frac else ''}"
