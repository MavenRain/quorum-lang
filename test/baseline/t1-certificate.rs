// Baseline sample T1 (S9 O127): a certificate check in Rust. A certificate
// holds the signature flags of the 3 members of a committee. The check
// accepts the certificate when at least t members sign.

type Cert = (bool, bool, bool);

fn signers(c: Cert) -> u64 {
    u64::from(c.0) + u64::from(c.1) + u64::from(c.2)
}

fn certified(t: u64, c: Cert) -> bool {
    t <= signers(c)
}

#[cfg(test)]
mod laws {
    use super::*;

    // Members 1 and 3 sign: the certificate is good for t = 2.
    #[test]
    fn two_of_three() {
        assert!(certified(2, (true, false, true)));
    }

    // Only member 3 signs: the certificate is not good for t = 2.
    #[test]
    fn one_of_three() {
        assert!(!certified(2, (false, false, true)));
    }

    // Each certificate is good for t = 0.
    #[test]
    fn zero_threshold() {
        let bits = [false, true];
        assert!(bits.iter().all(|&a| bits.iter().all(|&b| bits.iter().all(|&c| certified(0, (a, b, c))))));
    }
}
