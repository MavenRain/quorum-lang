// Baseline sample T2 (S9 O127): cast ballots and tally them into a bag, in
// Rust. A ballot is a bool vote. A bag of votes is the pair of counts
// (yes, no): it keeps each vote but not the order of the votes. The laws
// show one tally, and that the order of two casts does not change the bag.

type Bag = (u64, u64);

const EMPTY_BAG: Bag = (0, 0);

fn cast_vote(v: bool, b: Bag) -> Bag {
    if v { (b.0 + 1, b.1) } else { (b.0, b.1 + 1) }
}

fn tally3(v1: bool, v2: bool, v3: bool) -> Bag {
    cast_vote(v1, cast_vote(v2, cast_vote(v3, EMPTY_BAG)))
}

#[cfg(test)]
mod laws {
    use super::*;

    // Two yes votes and one no vote.
    #[test]
    fn tally_two_one() {
        assert_eq!(tally3(true, false, true), (2, 1));
    }

    // The order of two casts does not change the bag.
    #[test]
    fn cast_comm() {
        let bits = [false, true];
        let bags = [(0, 0), (1, 2), (5, 3)];
        assert!(bits.iter().all(|&u| bits.iter().all(|&v| bags.iter().all(|&b| cast_vote(u, cast_vote(v, b)) == cast_vote(v, cast_vote(u, b))))));
    }
}
