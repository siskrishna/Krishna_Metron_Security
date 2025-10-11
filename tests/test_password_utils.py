import pytest
from password_utils import evaluate_password, check_char_classes

def test_char_classes():
    s = "Ab1!"
    classes = check_char_classes(s)
    assert classes["has_upper"]
    assert classes["has_lower"]
    assert classes["has_digit"]
    assert classes["has_special"]

def test_evaluate_password_short():
    r = evaluate_password("aB3!", min_length=12)
    assert not r["ok"]
    assert any("Too short" in msg or "Too short" in msg for msg in r["reasons"])

def test_evaluate_password_good():
    p = "StrongPassw0rd!"
    r = evaluate_password(p, min_length=8)
    assert r["ok"] or (r["score"] > 0)
