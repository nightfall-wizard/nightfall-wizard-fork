//! Cut-through-compatible one-sided spend-authorization primitives.
//!
//! This module deliberately does NOT alter the consensus input format yet.
//! The current Ko signature remains authoritative until the stealth-excess
//! equation, offsets, retention horizon and storage/replay paths are integrated.
//!
//! The construction follows the LIP-0004 input-key relation:
//!
//! `K_input = Ki + H(Ki || Ko) * Ko`
//!
//! where:
//!
//! - Ki is a fresh ephemeral input key,
//! - Ko is the canonical one-time output key from the UTXO being spent,
//! - the signer knows both corresponding secret scalars.
//!
//! Consensus integration must additionally enforce the stealth balance.
//! This module alone is NOT sufficient to replace the existing Ko authorization.

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use nightfall_crypto::{generator_g, hash_multi, sig, Commitment, SchnorrSig};

use crate::tx::Transaction;

/// Domain separator for the candidate cut-through input authorization.
///
/// This primitive is not consensus-active yet. Once activated, changing this
/// value would be a consensus change.
pub const INPUT_AUTH_CHALLENGE_DOMAIN: &[u8] = b"nightfall:cutthrough:input-challenge:v1";

/// H(Ki || Ko), interpreted as a scalar.
///
/// Point validity is checked by [`input_verification_key`]. Keeping challenge
/// derivation independent makes the exact transcript explicit and testable.
pub fn input_auth_challenge(ki: &[u8; 32], ko: &[u8; 32]) -> Scalar {
    let h = hash_multi(INPUT_AUTH_CHALLENGE_DOMAIN, &[ki, ko]);
    Scalar::from_bytes_mod_order(h.0)
}

/// Calculate:
///
/// `K_input = Ki + H(Ki || Ko) * Ko`
///
/// Both Ki and Ko must be valid canonical compressed Ristretto points.
pub fn input_verification_key(ki: &[u8; 32], ko: &[u8; 32]) -> Option<RistrettoPoint> {
    let ki_point = CompressedRistretto(*ki).decompress()?;
    let ko_point = CompressedRistretto(*ko).decompress()?;
    let challenge = input_auth_challenge(ki, ko);

    Some(ki_point + ko_point * challenge)
}

/// Construct the corresponding secret:
///
/// `k_input = ki + H(Ki || Ko) * ko`
///
/// The supplied `ko_secret` must actually open canonical Ko. This guard is
/// wallet-side defence in depth; consensus verification uses only public data.
pub fn input_signing_secret(
    ki_secret: &Scalar,
    ko_secret: &Scalar,
    ko: &[u8; 32],
) -> Option<Scalar> {
    let canonical_ko = CompressedRistretto(*ko).decompress()?;

    if generator_g() * *ko_secret != canonical_ko {
        return None;
    }

    let ki = (generator_g() * *ki_secret).compress().to_bytes();
    let challenge = input_auth_challenge(&ki, ko);

    Some(*ki_secret + challenge * *ko_secret)
}

/// Produce candidate LIP-0004-style input authorization.
///
/// Returns `(Ki, signature)`.
///
/// This does not modify [`crate::Input`] and therefore has no effect on current
/// consensus validation.
pub fn sign_input_authorization(
    commit: &Commitment,
    ki_secret: &Scalar,
    ko_secret: &Scalar,
    canonical_ko: &[u8; 32],
) -> Option<([u8; 32], SchnorrSig)> {
    let ki = (generator_g() * *ki_secret).compress().to_bytes();

    let signing_secret = input_signing_secret(ki_secret, ko_secret, canonical_ko)?;

    let msg = Transaction::input_message(commit);
    let signature = sig::sign(&signing_secret, &generator_g(), &msg);

    Some((ki, signature))
}

/// Verify candidate input authorization against canonical Ko.
///
/// The caller must obtain `canonical_ko` from trusted UTXO state, never from
/// attacker-controlled replacement metadata.
pub fn verify_input_authorization(
    commit: &Commitment,
    ki: &[u8; 32],
    signature: &SchnorrSig,
    canonical_ko: &[u8; 32],
) -> bool {
    let Some(key) = input_verification_key(ki, canonical_ko) else {
        return false;
    };

    let msg = Transaction::input_message(commit);

    sig::verify(&key, &generator_g(), &msg, signature)
}

/// Sum compressed Ristretto public keys, failing closed if any key is
/// malformed.
///
/// This helper is intentionally private: callers should use the complete
/// stealth-balance verifier rather than constructing partial equations.
fn sum_public_keys(keys: &[[u8; 32]]) -> Option<RistrettoPoint> {
    let mut sum = RistrettoPoint::identity();

    for key in keys {
        sum += CompressedRistretto(*key).decompress()?;
    }

    Some(sum)
}

/// Construct the scalar stealth offset
///
/// `x' = Σks + Σki - Σko - Σe'`
///
/// corresponding to the public balance equation
///
/// `ΣKs + ΣKi - ΣKo = ΣE' + x'G`.
///
/// This is a construction helper only. Consensus must verify the public
/// equation independently.
pub fn stealth_offset_secret(
    sender_secrets: &[Scalar],
    input_ephemeral_secrets: &[Scalar],
    spent_output_secrets: &[Scalar],
    stealth_excess_secrets: &[Scalar],
) -> Scalar {
    let mut offset = Scalar::ZERO;

    for secret in sender_secrets {
        offset += *secret;
    }

    for secret in input_ephemeral_secrets {
        offset += *secret;
    }

    for secret in spent_output_secrets {
        offset -= *secret;
    }

    for secret in stealth_excess_secrets {
        offset -= *secret;
    }

    offset
}

/// Verify the aggregate stealth-authorization balance:
///
/// `ΣKs + ΣKi - ΣKo = ΣE' + x'G`.
///
/// * `sender_keys` are the sender authorization keys of retained outputs.
/// * `input_ephemeral_keys` are the `Ki` values carried by retained inputs.
/// * `spent_output_keys` are the canonical `Ko` values of those inputs.
/// * `stealth_excesses` are the retained stealth excess points `E'`.
/// * `stealth_offset` is the aggregate scalar offset `x'`.
///
/// Every compressed point is decompressed here and malformed material fails
/// closed. This function is deliberately independent of transaction grouping,
/// which allows offsets and excesses to compose under aggregation.
pub fn verify_stealth_balance(
    sender_keys: &[[u8; 32]],
    input_ephemeral_keys: &[[u8; 32]],
    spent_output_keys: &[[u8; 32]],
    stealth_excesses: &[Commitment],
    stealth_offset: &Scalar,
) -> bool {
    let Some(sender_sum) = sum_public_keys(sender_keys) else {
        return false;
    };

    let Some(input_sum) = sum_public_keys(input_ephemeral_keys) else {
        return false;
    };

    let Some(spent_sum) = sum_public_keys(spent_output_keys) else {
        return false;
    };

    let mut excess_sum = RistrettoPoint::identity();

    for excess in stealth_excesses {
        let Some(point) = excess.point() else {
            return false;
        };

        excess_sum += point;
    }

    let lhs = sender_sum + input_sum - spent_sum;
    let rhs = excess_sum + generator_g() * *stealth_offset;

    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use nightfall_crypto::{create_output, scan_output, WalletKeys};
    use nightfall_types::NetworkId;
    use rand::rngs::OsRng;

    fn owned_output() -> (WalletKeys, nightfall_crypto::Output, Scalar) {
        let receiver = WalletKeys::generate();

        let (output, _) = create_output(
            &receiver.address(),
            42_000,
            "phase2a",
            NetworkId::Devnet.proof_context(),
        )
        .expect("output");

        let discovered =
            scan_output(&receiver.view_key(), &output).expect("receiver must discover output");

        let ko_secret = discovered.spend_secret(&receiver);

        assert_eq!(
            (generator_g() * ko_secret).compress().to_bytes(),
            output.output_pk,
            "recovered spend secret must open canonical Ko",
        );

        (receiver, output, ko_secret)
    }

    #[test]
    fn legitimate_receiver_authorization_verifies() {
        let (_receiver, output, ko_secret) = owned_output();
        let ki_secret = Scalar::random(&mut OsRng);

        let (ki, signature) =
            sign_input_authorization(&output.commit, &ki_secret, &ko_secret, &output.output_pk)
                .expect("legitimate signing material");

        assert!(
            verify_input_authorization(&output.commit, &ki, &signature, &output.output_pk,),
            "legitimate receiver authorization must verify",
        );
    }

    #[test]
    fn authorization_is_bound_to_commitment() {
        let (_receiver, output, ko_secret) = owned_output();
        let ki_secret = Scalar::random(&mut OsRng);

        let (ki, signature) =
            sign_input_authorization(&output.commit, &ki_secret, &ko_secret, &output.output_pk)
                .expect("sign");

        let other_commit = Commitment::new(42_000, &Scalar::random(&mut OsRng));

        assert!(
            !verify_input_authorization(&other_commit, &ki, &signature, &output.output_pk,),
            "authorization must not move to another commitment",
        );
    }

    #[test]
    fn authorization_is_bound_to_canonical_ko() {
        let (_receiver, output, ko_secret) = owned_output();
        let ki_secret = Scalar::random(&mut OsRng);

        let (ki, signature) =
            sign_input_authorization(&output.commit, &ki_secret, &ko_secret, &output.output_pk)
                .expect("sign");

        let replacement_secret = Scalar::random(&mut OsRng);
        let replacement_ko = (generator_g() * replacement_secret).compress().to_bytes();

        assert!(
            !verify_input_authorization(&output.commit, &ki, &signature, &replacement_ko,),
            "substituting Ko must invalidate authorization",
        );
    }

    #[test]
    fn authorization_is_bound_to_ki() {
        let (_receiver, output, ko_secret) = owned_output();
        let ki_secret = Scalar::random(&mut OsRng);

        let (_ki, signature) =
            sign_input_authorization(&output.commit, &ki_secret, &ko_secret, &output.output_pk)
                .expect("sign");

        let replacement_ki = (generator_g() * Scalar::random(&mut OsRng))
            .compress()
            .to_bytes();

        assert!(
            !verify_input_authorization(
                &output.commit,
                &replacement_ki,
                &signature,
                &output.output_pk,
            ),
            "substituting Ki must invalidate authorization",
        );
    }

    #[test]
    fn wrong_ko_secret_is_rejected_before_signing() {
        let (_receiver, output, _ko_secret) = owned_output();

        let ki_secret = Scalar::random(&mut OsRng);
        let wrong_secret = Scalar::random(&mut OsRng);

        assert!(
            sign_input_authorization(&output.commit, &ki_secret, &wrong_secret, &output.output_pk,)
                .is_none(),
            "a secret which does not open canonical Ko must be rejected",
        );
    }

    #[test]
    fn malformed_public_keys_fail_closed() {
        let (_receiver, output, ko_secret) = owned_output();
        let ki_secret = Scalar::random(&mut OsRng);

        let (_ki, signature) =
            sign_input_authorization(&output.commit, &ki_secret, &ko_secret, &output.output_pk)
                .expect("sign");

        let malformed = [0xff; 32];

        assert!(
            !verify_input_authorization(&output.commit, &malformed, &signature, &output.output_pk,),
            "malformed Ki must fail",
        );

        let valid_ki = (generator_g() * ki_secret).compress().to_bytes();

        assert!(
            !verify_input_authorization(&output.commit, &valid_ki, &signature, &malformed,),
            "malformed Ko must fail",
        );
    }

    #[test]
    fn stealth_balance_accepts_exact_equation() {
        let ks = Scalar::random(&mut OsRng);
        let ki = Scalar::random(&mut OsRng);
        let ko = Scalar::random(&mut OsRng);
        let excess_secret = Scalar::random(&mut OsRng);

        let offset = stealth_offset_secret(&[ks], &[ki], &[ko], &[excess_secret]);

        let sender_keys = [(generator_g() * ks).compress().to_bytes()];
        let input_keys = [(generator_g() * ki).compress().to_bytes()];
        let spent_keys = [(generator_g() * ko).compress().to_bytes()];
        let excesses = [Commitment::from_point(generator_g() * excess_secret)];

        assert!(
            verify_stealth_balance(&sender_keys, &input_keys, &spent_keys, &excesses, &offset,),
            "exact stealth equation must verify",
        );
    }

    #[test]
    fn stealth_balance_composes_under_aggregation() {
        let ks1 = Scalar::random(&mut OsRng);
        let ki1 = Scalar::random(&mut OsRng);
        let ko1 = Scalar::random(&mut OsRng);
        let e1 = Scalar::random(&mut OsRng);

        let ks2 = Scalar::random(&mut OsRng);
        let ki2 = Scalar::random(&mut OsRng);
        let ko2 = Scalar::random(&mut OsRng);
        let e2 = Scalar::random(&mut OsRng);

        let x1 = stealth_offset_secret(&[ks1], &[ki1], &[ko1], &[e1]);

        let x2 = stealth_offset_secret(&[ks2], &[ki2], &[ko2], &[e2]);

        let aggregate_offset = x1 + x2;

        let sender_keys = [
            (generator_g() * ks1).compress().to_bytes(),
            (generator_g() * ks2).compress().to_bytes(),
        ];

        let input_keys = [
            (generator_g() * ki1).compress().to_bytes(),
            (generator_g() * ki2).compress().to_bytes(),
        ];

        let spent_keys = [
            (generator_g() * ko1).compress().to_bytes(),
            (generator_g() * ko2).compress().to_bytes(),
        ];

        let excesses = [
            Commitment::from_point(generator_g() * e1),
            Commitment::from_point(generator_g() * e2),
        ];

        assert!(
            verify_stealth_balance(
                &sender_keys,
                &input_keys,
                &spent_keys,
                &excesses,
                &aggregate_offset,
            ),
            "independent stealth balances must compose exactly",
        );
    }

    #[test]
    fn substituted_canonical_ko_breaks_stealth_balance() {
        let ks = Scalar::random(&mut OsRng);
        let ki = Scalar::random(&mut OsRng);
        let ko = Scalar::random(&mut OsRng);
        let e = Scalar::random(&mut OsRng);

        let offset = stealth_offset_secret(&[ks], &[ki], &[ko], &[e]);

        let sender_keys = [(generator_g() * ks).compress().to_bytes()];

        let input_keys = [(generator_g() * ki).compress().to_bytes()];

        let replacement_ko = Scalar::random(&mut OsRng);

        let spent_keys = [(generator_g() * replacement_ko).compress().to_bytes()];

        let excesses = [Commitment::from_point(generator_g() * e)];

        assert!(
            !verify_stealth_balance(&sender_keys, &input_keys, &spent_keys, &excesses, &offset,),
            "canonical Ko substitution must break the balance",
        );
    }

    #[test]
    fn wrong_stealth_offset_breaks_balance() {
        let ks = Scalar::random(&mut OsRng);
        let ki = Scalar::random(&mut OsRng);
        let ko = Scalar::random(&mut OsRng);
        let e = Scalar::random(&mut OsRng);

        let correct = stealth_offset_secret(&[ks], &[ki], &[ko], &[e]);

        let wrong = correct + Scalar::ONE;

        let sender_keys = [(generator_g() * ks).compress().to_bytes()];
        let input_keys = [(generator_g() * ki).compress().to_bytes()];
        let spent_keys = [(generator_g() * ko).compress().to_bytes()];
        let excesses = [Commitment::from_point(generator_g() * e)];

        assert!(
            !verify_stealth_balance(&sender_keys, &input_keys, &spent_keys, &excesses, &wrong,),
            "arbitrary offset adjustment must fail",
        );
    }

    #[test]
    fn malformed_stealth_balance_material_fails_closed() {
        let valid = Scalar::random(&mut OsRng);
        let valid_key = (generator_g() * valid).compress().to_bytes();

        let malformed = [0xff; 32];

        assert!(
            !verify_stealth_balance(&[malformed], &[valid_key], &[valid_key], &[], &Scalar::ZERO,),
            "malformed sender key must fail closed",
        );

        assert!(
            !verify_stealth_balance(&[valid_key], &[malformed], &[valid_key], &[], &Scalar::ZERO,),
            "malformed Ki must fail closed",
        );

        assert!(
            !verify_stealth_balance(&[valid_key], &[valid_key], &[malformed], &[], &Scalar::ZERO,),
            "malformed Ko must fail closed",
        );

        assert!(
            !verify_stealth_balance(
                &[valid_key],
                &[],
                &[valid_key],
                &[Commitment(malformed)],
                &Scalar::ZERO,
            ),
            "malformed stealth excess must fail closed",
        );
    }
}
