# Baseline sample T1 (S9 O127): a certificate check in Python. A certificate
# holds the signature flags of the 3 members of a committee. The check
# accepts the certificate when at least t members sign.

Cert = tuple[bool, bool, bool]


def signers(c: Cert) -> int:
    return sum(c)


def certified(t: int, c: Cert) -> bool:
    return t <= signers(c)


# Members 1 and 3 sign: the certificate is good for t = 2.
assert certified(2, (True, False, True))

# Only member 3 signs: the certificate is not good for t = 2.
assert not certified(2, (False, False, True))

# Each certificate is good for t = 0.
assert all(certified(0, (a, b, c)) for a in (False, True) for b in (False, True) for c in (False, True))
