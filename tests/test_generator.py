from password_utils import generate_password

def test_generate_length():
    p = generate_password(length=18)
    assert 16 <= len(p) <= 24

def test_generate_requirements():
    p = generate_password(length=16, no_symbols=False)
    # check at least one uppercase/lowercase/digit/special
    import re
    assert re.search(r"[A-Z]", p)
    assert re.search(r"[a-z]", p)
    assert re.search(r"\d", p)
    assert re.search(r"[!@#$%^&*()\-\_=+\[\]{};:,.<>/?]", p)
