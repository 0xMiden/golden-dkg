//! Reshares through public shares that corrupt participants force to the identity.

use ff::Field;
use golden_core::{
    deal, DkgConfig, DkgGroup,
    DkgInstanceKind::{Reshare, Zero},
};
use golden_curves::{JubjubGroup, Secp256k1Group};
use group::Group;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::sync::Mutex;

use super::support::{
    check_reshare, credential, decrypt, participant, Capture, ChosenScalars, Generation, PROOFS,
};

fn forced_zero_share<G: DkgGroup>() {
    let old = Generation::<G>::plain(&[1, 2, 3], 2, 1);
    // Dealer 2 and new receiver 1 are corrupt, one member of each committee.
    let config = old.reshare_config(&[1, 2], &[1, 2, 3], 2, vec![Reshare, Zero]);
    let capture = Capture(Mutex::default());
    let honest = old.dealing(&capture, &config, 1, &mut ChaCha20Rng::from_seed([2; 32]));
    let statement = capture.0.lock().unwrap().pop().unwrap();
    let received = decrypt(
        &statement,
        0,
        participant(1),
        &credential::<G>(1, participant(1)),
    );
    // The weights of dealers 1 and 2 at zero are 2 and -1, so f_2(1) = 2·f_1(1) zeroes
    // receiver 1's share while f_2(0) stays dealer 2's predecessor share.
    let slope = received.double() - old.share(participant(2));
    assert_eq!(
        G::Scalar::random(&mut ChosenScalars::new(vec![slope], 3)),
        slope
    );
    let corrupt = old.dealing(&PROOFS, &config, 2, &mut ChosenScalars::new(vec![slope], 3));
    let next = Generation::complete(1, config, vec![honest, corrupt]);
    assert_eq!(next.share(participant(1)), G::Scalar::ZERO);
    assert!(bool::from(next.public_share(1).is_identity()));
    check_reshare(&old, &next);

    for (dealers, seed) in [(&[1, 2][..], 4), (&[2, 3][..], 5)] {
        let config = next.reshare_config(dealers, &[1, 2, 3, 4], 3, vec![Reshare, Zero]);
        assert_eq!(
            DkgConfig::<G>::from_bytes(&config.to_bytes().unwrap()).unwrap(),
            config
        );
        let pinned = config
            .predecessor()
            .unwrap()
            .public_key_share(participant(1));
        assert!(bool::from(pinned.unwrap().is_identity()));
        let last = next.reshare(config, seed);
        check_reshare(&next, &last);
        assert_eq!(last.secret(), old.secret());
    }
}
both!(
    reshares_chain_through_a_forced_zero_share,
    forced_zero_share
);

fn rushing_plain_identity_share<G: DkgGroup>() {
    let config = Generation::<G>::plain_config(&[1, 2, 3], 2, 6);
    let capture = Capture(Mutex::default());
    let mut rng = ChaCha20Rng::from_seed([6; 32]);
    let mut own: Vec<_> = [1, 2]
        .into_iter()
        .map(|id| {
            let id = participant(id);
            deal(&capture, &config, id, &credential::<G>(0, id), &mut rng).unwrap()
        })
        .collect();
    // Participant 3 is corrupt and rushing: it decrypts its shares of the honest Random
    // sharings, then deals f_3 = c + a·x with f_3(3) cancelling their sum, so its share is zero.
    let me = participant(3);
    let received: G::Scalar = capture
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|statement| decrypt(statement, 0, me, &credential::<G>(0, me)))
        .sum();
    let constant = G::Scalar::from(5);
    let slope = -(received + constant) * G::Scalar::from(3).invert().unwrap();
    let mut chosen = ChosenScalars::new(vec![constant, slope], 7);
    own.push(deal(&PROOFS, &config, me, &credential::<G>(0, me), &mut chosen).unwrap());
    let plain = Generation::complete(0, config, own);
    assert_eq!(plain.share(me), G::Scalar::ZERO);
    assert!(bool::from(plain.public_share(3).is_identity()));
    assert!(!bool::from(plain.key().is_identity()));

    let config = plain.reshare_config(&[1, 3], &[1, 2, 3], 2, vec![Reshare, Zero]);
    let pinned = config.predecessor().unwrap().public_key_share(me);
    assert!(bool::from(pinned.unwrap().is_identity()));
    let next = plain.reshare(config, 8);
    check_reshare(&plain, &next);
}
both!(
    plain_outputs_with_a_forced_identity_share_are_predecessors,
    rushing_plain_identity_share
);
