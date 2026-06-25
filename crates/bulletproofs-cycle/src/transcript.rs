//! Merlin transcript helpers for the R1CS proof path, generic over a [`Cycle`].
//!
//! Append/challenge helpers are free functions rather than trait methods so
//! that the cycle type `C` can be supplied explicitly at the (rare) call sites
//! that do not already carry it on `self`. Domain separators carry no
//! cycle-specific data and live on a non-generic trait.

use crate::cycle::Cycle;
use crate::errors::ProofError;
use merlin::Transcript;

/// R1CS domain separators (cycle-independent).
pub trait R1csDomain {
    /// Inner-product domain separator for a length-`n` proof.
    fn innerproduct_domain_sep(&mut self, n: u64);

    /// R1CS domain separator.
    fn r1cs_domain_sep(&mut self);

    /// Single-phase R1CS domain separator.
    fn r1cs_1phase_domain_sep(&mut self);

    /// Two-phase R1CS domain separator.
    fn r1cs_2phase_domain_sep(&mut self);
}

impl R1csDomain for Transcript {
    fn innerproduct_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"ipp v1");
        self.append_u64(b"n", n);
    }

    fn r1cs_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs v1");
    }

    fn r1cs_1phase_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs-1phase");
    }

    fn r1cs_2phase_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs-2phase");
    }
}

/// Append a canonical scalar encoding under `label`.
pub fn append_scalar<C: Cycle>(
    transcript: &mut Transcript,
    label: &'static [u8],
    scalar: &C::Scalar,
) {
    transcript.append_message(label, &C::scalar_to_canonical(scalar));
}

/// Append a compressed point encoding under `label`.
pub fn append_point<C: Cycle>(
    transcript: &mut Transcript,
    label: &'static [u8],
    point: &C::Compressed,
) {
    transcript.append_message(label, C::compressed_as_bytes(point));
}

/// Reject the identity, then append the point under `label`.
pub fn validate_and_append_point<C: Cycle>(
    transcript: &mut Transcript,
    label: &'static [u8],
    point: &C::Compressed,
) -> Result<(), ProofError> {
    if C::compressed_is_identity(point) {
        return Err(ProofError::VerificationError);
    }
    transcript.append_message(label, C::compressed_as_bytes(point));
    Ok(())
}

/// Sample a wide-reduced challenge scalar under `label`.
pub fn challenge_scalar<C: Cycle>(transcript: &mut Transcript, label: &'static [u8]) -> C::Scalar {
    let mut buf = [0u8; 64];
    transcript.challenge_bytes(label, &mut buf);
    C::scalar_from_wide(&buf)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // The domain separators are part of the Fiat-Shamir soundness contract.
    // A typo here would silently break proof compatibility or shift every
    // challenge in the crate. The distinctness tests below pin the contract
    // without binding to merlin's exact challenge output (which would tie
    // the test to a specific STROBE implementation); they ensure each
    // domain-sep string produces a different challenge stream from the
    // others, and that `innerproduct_domain_sep` binds its length argument.

    fn challenge_after<F: FnOnce(&mut Transcript)>(label: &'static [u8], apply: F) -> [u8; 32] {
        let mut t = Transcript::new(b"bulletproofs-cycle-tests");
        apply(&mut t);
        let mut buf = [0u8; 32];
        t.challenge_bytes(label, &mut buf);
        buf
    }

    #[test]
    fn r1cs_domain_sep_yields_stable_bytes() {
        // Same input, two transcripts -> identical challenge bytes. This
        // pins determinism without locking in the exact STROBE output.
        let a = challenge_after(b"chal", |t| t.r1cs_domain_sep());
        let b = challenge_after(b"chal", |t| t.r1cs_domain_sep());
        assert_eq!(a, b);
    }

    #[test]
    fn r1cs_1phase_and_2phase_domain_seps_disagree() {
        // The two phase tags must not collide, otherwise a 1phase proof
        // could be replayed against a 2phase verifier transcript.
        let one = challenge_after(b"chal", |t| t.r1cs_1phase_domain_sep());
        let two = challenge_after(b"chal", |t| t.r1cs_2phase_domain_sep());
        assert_ne!(one, two, "1phase and 2phase domain seps must disagree");
    }

    #[test]
    fn innerproduct_domain_sep_binds_n() {
        // innerproduct_domain_sep appends n as a u64; two different n values
        // must produce different challenge streams, otherwise a length-mismatch
        // attacker could reuse a transcript.
        let small = challenge_after(b"chal", |t| t.innerproduct_domain_sep(8));
        let large = challenge_after(b"chal", |t| t.innerproduct_domain_sep(16));
        assert_ne!(small, large, "ipp domain sep must bind n");
    }

    #[test]
    fn domain_seps_do_not_collide_with_each_other() {
        // All four domain-sep strings must produce distinct challenge bytes.
        let r1cs = challenge_after(b"chal", |t| t.r1cs_domain_sep());
        let phase1 = challenge_after(b"chal", |t| t.r1cs_1phase_domain_sep());
        let phase2 = challenge_after(b"chal", |t| t.r1cs_2phase_domain_sep());
        let ipp = challenge_after(b"chal", |t| t.innerproduct_domain_sep(8));
        let all = [r1cs, phase1, phase2, ipp];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "domain seps {i} and {j} collide");
            }
        }
    }

    #[test]
    fn domain_seps_differ_from_bare_transcript() {
        // A transcript with no domain-sep applied must disagree with every
        // domain-sep'd transcript, otherwise the separator is a no-op.
        let bare = challenge_after(b"chal", |_| {});
        let r1cs = challenge_after(b"chal", |t| t.r1cs_domain_sep());
        let phase1 = challenge_after(b"chal", |t| t.r1cs_1phase_domain_sep());
        let phase2 = challenge_after(b"chal", |t| t.r1cs_2phase_domain_sep());
        let ipp = challenge_after(b"chal", |t| t.innerproduct_domain_sep(8));
        for (i, got) in [r1cs, phase1, phase2, ipp].iter().enumerate() {
            assert_ne!(
                *got, bare,
                "domain sep {i} is a no-op relative to bare transcript"
            );
        }
    }
}
