// Baseline sample T3 (S9 O127): an amendment keeps Core, in Rust. The
// rules are a pair (t, n): the threshold t and the count n of members. Core
// holds when 1 is at most t and t is at most n. The amendment adds one
// member and adds 1 to the threshold. The laws show that it keeps Core.

type Rules = (u64, u64);

fn core(s: Rules) -> bool {
    1 <= s.0 && s.0 <= s.1
}

fn amend(s: Rules) -> Rules {
    (s.0 + 1, s.1 + 1)
}

#[cfg(test)]
mod laws {
    use super::*;

    // The amendment of (2, 3) is (3, 4), and Core holds for it.
    #[test]
    fn amend_example() {
        assert_eq!(amend((2, 3)), (3, 4));
        assert!(core(amend((2, 3))));
    }

    // The amendment keeps Core.
    #[test]
    fn amend_keeps_core() {
        assert!((0..8).all(|t| (0..8).all(|n| !core((t, n)) || core(amend((t, n))))));
    }
}
