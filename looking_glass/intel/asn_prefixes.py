"""
asn_prefixes.py

Helper for ASN -> prefixes lookups using the existing pyasn DB.

- Assumes you already have a pyasn DB file built by your ASN builder
  (e.g. asn.py) and stored via get_cache_path().

- No separate build step: this is a thin read-only view on top of that DB.

API:
    get_prefixes(asn) -> {
        "asn": <int>,
        "prefixes": ["1.1.1.0/24", ...],
        "count": <int>,
        "total_ips": <int>
    } or None

CLI:
    python -m looking_glass.intel.asn_prefixes 13335
"""

from __future__ import annotations

import json
import re
import sys
import ipaddress
from functools import lru_cache
from typing import Any, Dict, List, Optional

import pyasn  # requires pyasn to be installed

from ..utility import get_cache_path

# Adjust this if your pyasn DB file has a different name
_ASN_DB_NAME = "asn_prefix.ipasn.dat"

_asn_db: Optional[pyasn.pyasn] = None


def _normalize_asn_val(v: Any) -> Optional[int]:
    """
    Normalize various ASN representations to integer, or None if invalid.

    Accepts:
        13335
        "13335"
        "AS13335"
        "as13335"
    """
    try:
        if isinstance(v, int):
            return int(v)
        s = str(v).strip()
        if not s:
            return None
        s = s.upper()
        if s.startswith("AS"):
            s = s[2:]
        s = re.sub(r"\D", "", s)
        return int(s) if s else None
    except Exception:
        return None


def _get_db() -> pyasn.pyasn:
    """
    Lazy-load the pyasn DB from the same cache dir used by other modules.
    """
    global _asn_db
    if _asn_db is not None:
        return _asn_db

    db_path = get_cache_path(_ASN_DB_NAME)
    _asn_db = pyasn.pyasn(db_path)
    return _asn_db


@lru_cache(maxsize=4096)
def get_prefixes(asn: Any) -> Optional[Dict[str, Any]]:
    """
    Return all prefixes announced by the given ASN.

    Returns:
        {
          "asn": 13335,
          "prefixes": [...],
          "count": <int>,
          "total_ipv4_ips": <int>,
          "total_ipv6_ips": <int>
        }
    or None if ASN not found / no prefixes known.
    """
    asn_i = _normalize_asn_val(asn)
    if asn_i is None:
        return None

    db = _get_db()

    try:
        # pyasn returns a list of prefix strings like '1.1.1.0/24'
        pfx_list = db.get_as_prefixes(asn_i)
    except Exception:
        return None

    if not pfx_list:
        return None

    prefixes: List[str] = []
    total_ipv4 = 0
    total_ipv6 = 0

    for p in pfx_list:
        try:
            net = ipaddress.ip_network(p, strict=False)
            prefixes.append(str(net.with_prefixlen))
            if net.version == 4:
                total_ipv4 += int(net.num_addresses)
            else:
                total_ipv6 += int(net.num_addresses)
        except Exception:
            continue

    if not prefixes:
        return None

    prefixes = sorted(set(prefixes))

    return {
        "asn": int(asn_i),
        "prefixes": prefixes,
        "count": len(prefixes),
        "total_ipv4_ips": int(total_ipv4),
        "total_ipv6_ips": int(total_ipv6),
    }


def main(argv: Optional[List[str]] = None) -> None:
    """
    CLI entry point.

    Example:
        python -m looking_glass.intel.asn_prefixes 13335
    """
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("Usage: python -m looking_glass.intel.asn_prefixes <ASN>", file=sys.stderr)
        raise SystemExit(1)

    asn = argv[0]
    result = get_prefixes(asn)
    if result is None:
        print(json.dumps({"ok": False, "asn": asn, "result": None}))
        raise SystemExit(2)

    out = {
        "ok": True,
        "asn": result["asn"],
        "count": result["count"],
        "total_ipv4_ips": result["total_ipv4_ips"],
        "total_ipv6_ips": result["total_ipv6_ips"],
        "prefixes": result["prefixes"],
    }
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()