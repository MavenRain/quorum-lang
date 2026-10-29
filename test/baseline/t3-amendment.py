# Baseline sample T3 (S9 O127): an amendment keeps Core, in Python. The
# rules are a pair (t, n): the threshold t and the count n of members. Core
# holds when 1 is at most t and t is at most n. The amendment adds one
# member and adds 1 to the threshold. The laws show that it keeps Core.

Rules = tuple[int, int]


def core(s: Rules) -> bool:
    return 1 <= s[0] and s[0] <= s[1]


def amend(s: Rules) -> Rules:
    return (s[0] + 1, s[1] + 1)


# The amendment of (2, 3) is (3, 4), and Core holds for it.
assert amend((2, 3)) == (3, 4) and core(amend((2, 3)))

# The amendment keeps Core.
assert all(core(amend((t, n))) for t in range(8) for n in range(8) if core((t, n)))
