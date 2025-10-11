"""
password_utils.py

Contains:
 - Password strength checker (length, char classes, breach list check placeholder).
 - Password generator (secure, policy-driven).
"""

import secrets
import string
import re
import hashlib

# Minimum policy values (tuneable)
DEFAULT_MIN_LENGTH = 12
GEN_MIN_LENGTH = 16
GEN_MAX_LENGTH = 24

# special characters allowed for generator (common safe set)
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{};:,.<>/?"

# simple regex helpers
UPPER_RE = re.compile(r"[A-Z]")
LOWER_RE = re.compile(r"[a-z]")
DIGIT_RE = re.compile(r"\d")
SPECIAL_RE = re.compile(r"[{}]".format(re.escape(SPECIAL_CHARS)))

def check_char_classes(password: str) -> dict:
    """
    Return a dict describing whether password contains required classes.
    """
    return {
        "has_upper": bool(UPPER_RE.search(password)),
        "has_lower": bool(LOWER_RE.search(password)),
        "has_digit": bool(DIGIT_RE.search(password)),
        "has_special": bool(SPECIAL_RE.search(password)),
    }

def evaluate_password(password: str, min_length: int = DEFAULT_MIN_LENGTH, check_breach: bool = False, hibp_check_fn=None) -> dict:
    """
    Evaluate password against policy.

    Returns a dict with:
      - ok: bool
      - reasons: list of strings explaining failures (or success message)
      - score: rough integer (0..100)
      - sha1: SHA1 uppercase hex of password (useful for hibp)
    """
    reasons = []
    score = 0

    if not isinstance(password, str):
        reasons.append("Password must be a string.")
        return {"ok": False, "reasons": reasons, "score": 0}

    length = len(password)
    if length < min_length:
        reasons.append(f"Too short (minimum {min_length} characters).")
    else:
        score += 30

    classes = check_char_classes(password)
    if classes["has_upper"]:
        score += 15
    else:
        reasons.append("Missing uppercase character.")

    if classes["has_lower"]:
        score += 15
    else:
        reasons.append("Missing lowercase character.")

    if classes["has_digit"]:
        score += 15
    else:
        reasons.append("Missing digit.")

    if classes["has_special"]:
        score += 15
    else:
        reasons.append("Missing special character (e.g., !@#$%).")

    # Very basic entropy-based suggestion: length bonus
    if length >= 16:
        score += 10

    # compute SHA1 for optional breach check (HIBP uses SHA1)
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    if check_breach:
        # hibp_check_fn should be a callable that accepts SHA1 and returns True if found
        if hibp_check_fn is None:
            reasons.append("Breach check requested but no hibp_check_fn provided.")
        else:
            try:
                breached = hibp_check_fn(sha1)
            except Exception as e:
                # Don't leak the password or full error in logs; raise or return an informative message
                reasons.append(f"Error checking breach status: {str(e)}")
                breached = False
            if breached:
                reasons.append("Password found in breach database (HIBP).")
                score = max(0, score - 50)

    ok = len(reasons) == 0
    if ok:
        reasons = ["Password passed checks."]
    return {"ok": ok, "reasons": reasons, "score": score, "sha1": sha1}

def generate_password(length: int = 16, no_symbols: bool = False, require_each_class: bool = True) -> str:
    """
    Generate a strong random password. Uses Python's secrets module.
    - length: 16..24 (will clamp automatically)
    - no_symbols: if True, omit special characters
    - require_each_class: guarantee at least one char from each required class
    """
    if length < GEN_MIN_LENGTH:
        length = GEN_MIN_LENGTH
    if length > GEN_MAX_LENGTH:
        length = GEN_MAX_LENGTH

    alphabet = string.ascii_letters + string.digits
    symbols = SPECIAL_CHARS
    if not no_symbols:
        alphabet += symbols

    # If we must ensure at least one of each class, pick them first then fill rest
    password_chars = []
    if require_each_class:
        password_chars.append(secrets.choice(string.ascii_uppercase))
        password_chars.append(secrets.choice(string.ascii_lowercase))
        password_chars.append(secrets.choice(string.digits))
        if not no_symbols:
            password_chars.append(secrets.choice(symbols))
        else:
            # if no symbols requested, add extra digit or letter
            password_chars.append(secrets.choice(string.ascii_lowercase))

    # fill remaining positions
    while len(password_chars) < length:
        password_chars.append(secrets.choice(alphabet))

    # shuffle securely
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)
