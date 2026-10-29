# Baseline sample T2 (S9 O127): cast ballots and tally them into a bag, in
# Python. A ballot is a bool vote. A bag of votes is the pair of counts
# (yes, no): it keeps each vote but not the order of the votes. The laws
# show one tally, and that the order of two casts does not change the bag.

Bag = tuple[int, int]

EMPTY_BAG: Bag = (0, 0)


def cast_vote(v: bool, b: Bag) -> Bag:
    return (b[0] + 1, b[1]) if v else (b[0], b[1] + 1)


def tally3(v1: bool, v2: bool, v3: bool) -> Bag:
    return cast_vote(v1, cast_vote(v2, cast_vote(v3, EMPTY_BAG)))


# Two yes votes and one no vote.
assert tally3(True, False, True) == (2, 1)

# The order of two casts does not change the bag.
assert all(
    cast_vote(u, cast_vote(v, b)) == cast_vote(v, cast_vote(u, b))
    for u in (False, True)
    for v in (False, True)
    for b in ((0, 0), (1, 2), (5, 3))
)
