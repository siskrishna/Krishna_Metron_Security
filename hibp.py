"""
hibp.py

Implements k-anonymity SHA1 range lookup to HaveIBeenPwned's Pwned Passwords API.

Docs: https://haveibeenpwned.com/API/v3#PwnedPasswords
We implement the unauthenticated range API:
  - compute SHA1 of password (already done upstream)
  - send first 5 hex chars to https://api.pwnedpasswords.com/range/{prefix}
  - receive list of suffix:count lines, search for suffix match

Important: We never send the full password or full hash to the API.
"""

import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"
# Optionally set a User-Agent per HIPB API guidance
DEFAULT_HEADERS = {"User-Agent": "Krishna_Metron_Security_Tool/1.0"}

def check_sha1_in_hibp(sha1_upper: str, headers: dict = None, timeout: float = 5.0) -> bool:
    """
    Given the uppercase SHA1 hex string of the password, return True if the
    suffix is present in the HIBP response (i.e., password was pwned).
    """
    if headers is None:
        headers = DEFAULT_HEADERS
    if len(sha1_upper) != 40:
        raise ValueError("sha1 must be 40-hex uppercase string")

    prefix = sha1_upper[:5]
    suffix = sha1_upper[5:]

    url = HIBP_RANGE_URL.format(prefix)
    resp = requests.get(url, headers=headers, timeout=timeout)
    if resp.status_code != 200:
        raise RuntimeError(f"HIBP range API returned status code {resp.status_code}")

    # Response is lines like: "ABCDEF0123456789...:1234"
    # Compare case-insensitively (we use uppercase)
    body = resp.text.splitlines()
    for line in body:
        if not line:
            continue
        parts = line.split(":")
        if len(parts) != 2:
            continue
        found_suffix, count = parts[0].strip(), parts[1].strip()
        if found_suffix.upper() == suffix.upper():
            # Found — breached
            return True
    return False
