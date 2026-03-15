use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use ark_std::collections::{BTreeMap, BTreeSet};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ps_sig::blind_signature::*;
use ps_sig::keys::{keygen, Params};
use ps_sig::pok_sig::*;
use ps_sig::pok_vc::ProverCommitting;
use sha2::Sha256;

#[test]
fn test_scenario_1() {
    fn check<E: Pairing>() {
        // User request signer to sign 10 messages where signer knows only 8 messages, the rest 2 are given in a form of commitment.
        // Once user gets the signature, it engages in a proof of knowledge of signature with a verifier.
        // The user also reveals to the verifier some of the messages.
        let count_msgs = 10;
        let count_blinded_msgs = 2;
        let params = Params::<E>::new::<Sha256>("test".as_bytes());
        let mut rng = StdRng::seed_from_u64(0u64);
        let (sk, vk) = keygen(count_msgs, &params, &mut rng);

        let blinding_key = BlindingKey::new(&sk, &params);
        let msgs = (0..count_msgs)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect::<Vec<E::ScalarField>>();
        let blinding = E::ScalarField::rand(&mut rng);

        // User commits to some messages
        let mut comm = E::G1::from(blinding_key.Y[0]) * msgs[0];
        for i in 1..count_blinded_msgs {
            comm += E::G1::from(blinding_key.Y[i]) * msgs[i];
        }
        comm += E::G1::from(params.g) * blinding;
        let comm = comm.into_affine();

        {
            // User and signer engage in a proof of knowledge for the above commitment `comm`
            let mut bases = Vec::<E::G1Affine>::new();
            let mut hidden_msgs = Vec::<E::ScalarField>::new();
            for i in 0..count_blinded_msgs {
                bases.push(blinding_key.Y[i].clone());
                hidden_msgs.push(msgs[i].clone());
            }
            bases.push(params.g.clone());
            hidden_msgs.push(blinding.clone());

            // User creates a random commitment, computes challenge and response. The proof of knowledge consists of commitment and responses
            let mut committing = ProverCommitting::<E::G1Affine>::new();
            for b in &bases {
                committing.commit_random(*b, &mut rng);
            }
            let committed = committing.finish();

            // Note: The challenge may come from the main protocol
            let mut comm_bytes = Vec::new();
            comm.serialize_compressed(&mut comm_bytes).unwrap();
            let chal = committed.gen_challenge::<Sha256>(&comm_bytes).unwrap();

            let proof = committed.gen_proof(chal, hidden_msgs.as_slice()).unwrap();

            // Signer verifies the proof of knowledge.
            assert!(proof.verify(bases.as_slice(), comm, chal).unwrap());
        }

        // Get signature, unblind it and then verify.
        let sig_blinded = BlindSignature::new(
            &comm,
            &msgs.as_slice()[count_blinded_msgs..count_msgs],
            &sk,
            &blinding_key,
            &params,
            &mut rng,
        )
        .unwrap();
        let sig_unblinded = BlindSignature::unblind(&sig_blinded, &blinding);
        assert!(sig_unblinded.verify(&msgs, &vk, &params).unwrap());

        // Do a proof of knowledge of the signature and also reveal some of the messages.
        let mut revealed_msg_indices = BTreeSet::new();
        revealed_msg_indices.insert(4);
        revealed_msg_indices.insert(6);
        revealed_msg_indices.insert(9);

        let pok = PoKOfSignature::init(
            &sig_unblinded,
            &vk,
            &params,
            msgs.clone(),
            None,
            revealed_msg_indices.clone(),
            &mut rng,
        )
        .unwrap();

        // Generate challenge - both prover and verifier should compute the same value
        let chal_prover = pok.gen_challenge::<Sha256>().unwrap();

        let proof = pok.gen_proof(chal_prover).unwrap();

        // Verifier independently generates the same challenge
        let chal_verifier = proof
            .gen_challenge::<Sha256>(revealed_msg_indices.clone(), &vk, &params)
            .unwrap();

        // Verify challenges match (critical security check)
        assert_eq!(
            chal_prover, chal_verifier,
            "Prover and verifier must generate identical challenges"
        );

        let mut revealed_msgs = BTreeMap::new();
        for i in &revealed_msg_indices {
            revealed_msgs.insert(*i, msgs[*i]);
        }
        assert!(proof
            .verify(&vk, &params, revealed_msgs.clone(), &chal_verifier)
            .unwrap());
    }

    check::<ark_bls12_381::Bls12_381>();
    check::<ark_bls12_377::Bls12_377>();
}
