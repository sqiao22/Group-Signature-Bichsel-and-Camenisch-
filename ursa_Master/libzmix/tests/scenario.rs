extern crate amcl_wrapper;
extern crate zmix;
extern crate ursa;

use amcl_wrapper::group_elem::GroupElement;
use std::collections::{HashMap, HashSet};
use zmix::signatures::prelude::*;
use zmix::signatures::ps::prelude::*;


use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};

use ursa::signatures::ed25519::*;



// use ursa::cl::issuer::Issuer;
// use ursa::cl::prover::Prover;
// use ursa::cl::verifier::Verifier;
// use ursa::cl::*;
// use std::time::{Duration, Instant};





// fn print_type_of<T>(_: &T) {
//     println!("{}", std::any::type_name::<T>())
// }

// pub fn GSetup (){
//     let count_msgs = 10;
//     let tesss =keygen(count_msgs, "test".as_bytes());
//     print_type_of(&tesss);
// }



//real
// pub fn GSetup (count_msgs: usize, label: &[u8])->(Gpk, Gmsk){
//     let (gpk, gmsk) = For_GSetup(count_msgs, label);
//     // print_type_of(&gpk);
//     (gpk, gmsk)
// }

//
pub fn GSetup (count_msgs: usize, label: &[u8])->(PublicKey,SecretKey){
    let (gpk, gmsk) = keygen(count_msgs, label);
    // print_type_of(&gpk);
    (gpk, gmsk)
}

pub fn PKIJoin (count_msgs: usize, label: &[u8])->(PublicKey,SecretKey){
    let (upk_i, usk_i) = keygen(count_msgs, label);
    let msg = FieldElementVector::random(count_msgs);
    let sign_usk_i=Signature::new(msg.as_slice(), &usk_i, &upk_i).unwrap();
    let check=sign_usk_i.verify(msg.as_slice(),&upk_i).unwrap();
    println!("usk_i, upk_i pair checks out: {}",check);
    (upk_i, usk_i)
}


pub fn GJoin (gpk: PublicKey,gmsk: SecretKey, upk_i:PublicKey ,usk_i:SecretKey)->(){
    ////////////user generates a secret key
    let ski= FieldElement::random();
    ////////////user sends the pair τ, τ, 
    let tow=&gpk.g * &ski;
    //fake
    let mut tow_tilde = vec![];
    for item in gpk.Y_tilde {
        // println!("{:?}", item);
        tow_tilde.push(&item * &ski);
    }
    //real
    //let tow_tilde= &gpk.Y_tilde * &ski;
    //////////////sign using usk_i
    println!("{:?}", tow);
    // let sign=Signature::new(tow, &usk_i, &upk_i).unwrap();
    // let s = FieldElementVector::random(12);
    // println!("{:?}",s);

}


#[test]
fn test_scenario_1() {
    // User request signer to sign 10 messages where signer knows only 8 messages, the other 2 are given in a form of commitment.
    // Once user receives the signature, it engages in a proof of knowledge of signature with a verifier.
    // The user also reveals to the verifier some of the messages.
    let count_msgs = 10;
    let committed_msgs = 2;
    let label="test".as_bytes();
    let (gpk, gmsk) = GSetup(count_msgs,label);

    let (upk_i, usk_i)=PKIJoin(1,label);


    // println!("{}",gpk.X_tilde);
    // println!("{:?}",gpk.Y_tilde);
    // println!("{:?}",gpk.Y);
    // println!("{}",sk.X);
    // println!("{:?}",gpk.g);
    // println!("{:?}",gpk.g_tilde);

    GJoin (gpk.clone(),gmsk.clone(), upk_i,usk_i);




    let msgs = SignatureMessageVector::random(count_msgs);
    let blinding = SignatureMessage::random();

    // User commits to some messages
    let mut comm = SignatureGroup::new();
    for i in 0..committed_msgs {
        comm += &gpk.Y[i] * &msgs[i];
    }
    comm += &gpk.g * &blinding;

    {
        // User and signer engage in a proof of knowledge for the above commitment `comm`
        let mut bases = Vec::<SignatureGroup>::new();
        let mut hidden_msgs = Vec::<SignatureMessage>::new();
        for i in 0..committed_msgs {
            bases.push(gpk.Y[i].clone());
            hidden_msgs.push(msgs[i].clone());
        }
        bases.push(gpk.g.clone());
        hidden_msgs.push(blinding.clone());

        // User creates a random commitment, computes challenge and response. The proof of knowledge consists of commitment and responses
        let mut committing = ProverCommittingSignatureGroup::new();
        for b in &bases {
            committing.commit(b, None);
        }
        let committed = committing.finish();

        // Note: The challenge may come from the main protocol
        let chal = committed.gen_challenge(comm.to_bytes());

        let proof = committed.gen_proof(&chal, hidden_msgs.as_slice()).unwrap();

        // Signer verifies the proof of knowledge.
        assert!(proof.verify(bases.as_slice(), &comm, &chal).unwrap());
    }

    // Get signature, unblind it and then verify.
    let sig_blinded = Signature::new_with_committed_messages(
        &comm,
        &msgs.as_slice()[committed_msgs..count_msgs],
        &gmsk,
        &gpk,
    )
    .unwrap();
    let sig_unblinded = sig_blinded.get_unblinded_signature(&blinding);
    assert!(sig_unblinded.verify(msgs.as_slice(), &gpk).unwrap());

    // Do a proof of knowledge of the signature and also reveal some of the messages.
    let mut revealed_msg_indices = HashSet::new();
    revealed_msg_indices.insert(4);
    revealed_msg_indices.insert(6);
    revealed_msg_indices.insert(9);

    let pok = PoKOfSignature::init(
        &sig_unblinded,
        &gpk,
        msgs.as_slice(),
        None,
        revealed_msg_indices.clone(),
    )
    .unwrap();

    let chal = SignatureMessage::from_msg_hash(&pok.to_bytes());

    let proof = pok.gen_proof(&chal).unwrap();

    let mut revealed_msgs = HashMap::new();
    for i in &revealed_msg_indices {
        revealed_msgs.insert(i.clone(), msgs[*i].clone());
    }
    assert!(proof.verify(&gpk, revealed_msgs.clone(), &chal).unwrap());
}
