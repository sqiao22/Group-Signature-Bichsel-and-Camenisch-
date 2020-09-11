extern crate amcl_wrapper;
extern crate zmix;
extern crate ursa;


use amcl_wrapper::group_elem::GroupElement;
use std::collections::{HashMap, HashSet};
use zmix::signatures::prelude::*;
use zmix::signatures::ps::prelude::*;


use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};

use ursa::signatures::ed25519::*;

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

use amcl_wrapper::extension_field_gt::GT;


use amcl_wrapper::ECCurve::big::BIG;

// use ursa::cl::issuer::Issuer;
// use ursa::cl::prover::Prover;
// use ursa::cl::verifier::Verifier;
// use ursa::cl::*;
// use std::time::{Duration, Instant};


pub fn GSetup (count_msgs: usize, label: &[u8])->(Gpk, Gmsk){
    println!("GSetup Start.........");
    let (gpk, gmsk) = For_GSetup(count_msgs, label);
    // print_type_of(&gpk);
    println!("GSetup Successful!");
    (gpk, gmsk)
}

pub fn PKIJoin (count_msgs: usize, label: &[u8])->(PublicKey,SecretKey){
    println!("PKIJoin Start.........");
    let (upk_i, usk_i) = keygen(count_msgs, label);
    let msg = FieldElementVector::random(count_msgs);
    let sign_usk_i=Signature::new(msg.as_slice(), &usk_i, &upk_i).unwrap();
    // let check=sign_usk_i.verify(msg.as_slice(),&upk_i).unwrap();
    // println!("usk_i, upk_i pair checks out: {}",check);
    println!("PKIJoin Successful!");
    (upk_i, usk_i)
}

//Need to convert τ into number so it can be signed
pub fn hashing(s: DefaultHasher,message: amcl_wrapper::group_elem_g1::G1)->(u64){
    let mut hasher = s.clone();
    message.hash(&mut hasher);
    hasher.finish()
}
// Need this so tow can be a FieldElementVector
pub fn sign_usk_i(s:DefaultHasher,tow:amcl_wrapper::group_elem_g1::G1,usk_i:SecretKey, upk_i:PublicKey)->(Signature){
    let tow_hash=hashing(s.clone(),tow.clone());
    // println!("{:?}", tow_hash);
    let mut msg=FieldElementVector::new(0);
    // println!("{:?}", tow_hash % 20 );
    for i in 0..20 {
        if i==tow_hash % 20 {
            msg.push(FieldElement::zero());
        }
        else{
            msg.push(FieldElement::one());
        }
    }
    // println!("{:?}", msg);
    Signature::new(msg.as_slice(), &usk_i, &upk_i).unwrap()
}
// Check sign_usk_i signature
pub fn verify_usk_i(signature_usk_i: Signature,s:DefaultHasher,tow:amcl_wrapper::group_elem_g1::G1, upk_i:PublicKey)->(bool){
    
    let tow_hash=hashing(s.clone(),tow.clone());
    let mut msg=FieldElementVector::new(0);
    // println!("{:?}", tow_hash % 20 );
    for i in 0..20 {
        if i==tow_hash % 20 {
            msg.push(FieldElement::zero());
        }
        else{
            msg.push(FieldElement::one());
        }
    }

    let check=signature_usk_i.verify(msg.as_slice(),&upk_i).unwrap();
    check
}

pub fn GJoin (i: usize, gpk: Gpk,gmsk: Gmsk, upk_i:PublicKey ,usk_i:SecretKey)->(){
    println!("GJoin Start.........");
    //USER generates a secret key,τ, τ_tidle, η and send τ, τ_tidle and η
    println!("USER create ski, τ, τ_tidle and η and send τ, τ_tidle and η");
    let ski= FieldElement::random();
    let tow=&gpk.g * &ski;
    let tow_tilde= &gpk.Y_tilde * &ski;
    let mut s = DefaultHasher::new();
    let n =sign_usk_i(s.clone(), tow.clone(), usk_i.clone(), upk_i.clone());
    // let m =sign_usk_i(s.clone(), tow.clone(), usk_i.clone(), upk_i.clone());
    // let check1=verify_usk_i(n.clone(),s.clone(), tow.clone(),upk_i.clone());
    // let check2=verify_usk_i(m.clone(),s.clone(), tow.clone(),upk_i.clone());
    // println!("{:?}",check1);
    // println!("{:?}",check2);
    

    println!("GROUP MANAGER tests e(τ, Y_tilde) =e(g, τ_tilde)");
    //GROUP MANAGER tests e(τ, Y_tilde) =e(g, τ_tilde)
    let res = GT::ate_pairing(&tow, &gpk.Y_tilde);
    let res2 = GT::ate_pairing(&gpk.g, &tow_tilde);
    // println!("{:?}", res==res2);


    println!("USER Start Proof of knowledge of ski");
    //User start proof of knowledge for ski
    // let pk=(&tow, &gpk.Y_tilde);
    // test_PoK_multiple_sigs(pk,ski);
    test_sigmaProtocol(gpk.g.clone(),ski.clone(),tow.clone());
    

    println!("Group Manager Generates u, σ");
    //Group MANAGER u, σ←(σ1,σ2)←(gu,(gx·(τ)y)u) 
    let u= FieldElement::random();
    let sigma1=&gpk.g * &u;
    let sigma2=&gpk.g * &gmsk.x + &tow * &gmsk.y * &u;
    let sigma=(&sigma1,&sigma2);


    println!("Group Manager Stores i,τ,η,τ_tilde and hash");
    //Group Manager Store (i,τ,η,τ_tilde) need to add s for hasher
    let secret_register=(i,tow,n,tow_tilde,s);

    println!("USER Stores ski,σ,e(σ1,Y_tilde)");
    //User Store (ski,σ,e(σ1,Y_tilde))
    let gsk_i=(ski,sigma,GT::ate_pairing(&sigma1,&gpk.Y_tilde));

    println!("GJoin Successful!");

}

//using sigma protocol, since PoKOfSignature requires vk and sk pair, when ski is the only thing given
pub fn test_sigmaProtocol(g:amcl_wrapper::group_elem_g1::G1,y:FieldElement,Y:amcl_wrapper::group_elem_g1::G1)->(){
    //Proofer/USER calculate r and A
    let r = FieldElement::random();
    let A=&g*&r;
    //Proofer send A to Verifer
    //Verifer/GROUP MANAGER Calculate cha
    let cha = FieldElement::random();
    //Verifer send cha to Proofer
    //Proofer calculate rsp
    let rsp=&r-&y*&cha;
    //Proofer send rsp to Verifer
    // Verifer check if A=g^rsp*Y^cha
    let Check=&g*&rsp+&Y*&cha;
    println!("Proof of USER knowing ski: {:?}", A==Check);

}

// fn test_PoK_multiple_sigs(gpk: Gpk, gmsk: Gmsk) {
//     // Prove knowledge of multiple signatures together (using the same challenge)
//     let count_msgs = 5;
//     let (vk, sk) = keygen(count_msgs, "test".as_bytes());

//     let msgs_1 = FieldElementVector::random(count_msgs);
//     let sig_1 = Signature::new(msgs_1.as_slice(), &sk, &vk).unwrap();
//     assert!(sig_1.verify(msgs_1.as_slice(), &vk).unwrap());

//     let msgs_2 = FieldElementVector::random(count_msgs);
//     let sig_2 = Signature::new(msgs_2.as_slice(), &sk, &vk).unwrap();
//     assert!(sig_2.verify(msgs_2.as_slice(), &vk).unwrap());

//     let pok_1 =
//         PoKOfSignature::init(&sig_1, &vk, msgs_1.as_slice(), None, HashSet::new()).unwrap();
//     let pok_2 =
//         PoKOfSignature::init(&sig_2, &vk, msgs_2.as_slice(), None, HashSet::new()).unwrap();

//     let mut chal_bytes = vec![];
//     chal_bytes.append(&mut pok_1.to_bytes());
//     chal_bytes.append(&mut pok_2.to_bytes());

//     let chal = FieldElement::from_msg_hash(&chal_bytes);

//     let proof_1 = pok_1.gen_proof(&chal).unwrap();
//     let proof_2 = pok_2.gen_proof(&chal).unwrap();

//     assert!(proof_1.verify(&vk, HashMap::new(), &chal).unwrap());
//     assert!(proof_2.verify(&vk, HashMap::new(), &chal).unwrap());
// }




#[test]
fn test_scenario_1() {
    // User request signer to sign 10 messages where signer knows only 8 messages, the other 2 are given in a form of commitment.
    // Once user receives the signature, it engages in a proof of knowledge of signature with a verifier.
    // The user also reveals to the verifier some of the messages.
    let count_msgs = 10;
    let committed_msgs = 2;
    let label="test".as_bytes();
    let (gpk, gmsk) = GSetup(count_msgs,label);

    let (upk_i, usk_i)=PKIJoin(20,label);


    // println!("{}",gpk.X_tilde);
    // println!("{:?}",gpk.Y_tilde);
    // println!("{:?}",gpk.Y);
    // println!("{}",sk.X);
    // println!("{:?}",gpk.g);
    // println!("{:?}",gpk.g_tilde);
    let user_id=1;
    GJoin (user_id,gpk.clone(),gmsk.clone(), upk_i,usk_i);




    // let msgs = SignatureMessageVector::random(count_msgs);
    // let blinding = SignatureMessage::random();

    // // User commits to some messages
    // let mut comm = SignatureGroup::new();
    // for i in 0..committed_msgs {
    //     comm += &gpk.Y[i] * &msgs[i];
    // }
    // comm += &gpk.g * &blinding;

    // {
    //     // User and signer engage in a proof of knowledge for the above commitment `comm`
    //     let mut bases = Vec::<SignatureGroup>::new();
    //     let mut hidden_msgs = Vec::<SignatureMessage>::new();
    //     for i in 0..committed_msgs {
    //         bases.push(gpk.Y[i].clone());
    //         hidden_msgs.push(msgs[i].clone());
    //     }
    //     bases.push(gpk.g.clone());
    //     hidden_msgs.push(blinding.clone());

    //     // User creates a random commitment, computes challenge and response. The proof of knowledge consists of commitment and responses
    //     let mut committing = ProverCommittingSignatureGroup::new();
    //     for b in &bases {
    //         committing.commit(b, None);
    //     }
    //     let committed = committing.finish();

    //     // Note: The challenge may come from the main protocol
    //     let chal = committed.gen_challenge(comm.to_bytes());

    //     let proof = committed.gen_proof(&chal, hidden_msgs.as_slice()).unwrap();

    //     // Signer verifies the proof of knowledge.
    //     assert!(proof.verify(bases.as_slice(), &comm, &chal).unwrap());
    // }

    // // Get signature, unblind it and then verify.
    // let sig_blinded = Signature::new_with_committed_messages(
    //     &comm,
    //     &msgs.as_slice()[committed_msgs..count_msgs],
    //     &gmsk,
    //     &gpk,
    // )
    // .unwrap();
    // let sig_unblinded = sig_blinded.get_unblinded_signature(&blinding);
    // assert!(sig_unblinded.verify(msgs.as_slice(), &gpk).unwrap());

    // // Do a proof of knowledge of the signature and also reveal some of the messages.
    // let mut revealed_msg_indices = HashSet::new();
    // revealed_msg_indices.insert(4);
    // revealed_msg_indices.insert(6);
    // revealed_msg_indices.insert(9);

    // let pok = PoKOfSignature::init(
    //     &sig_unblinded,
    //     &gpk,
    //     msgs.as_slice(),
    //     None,
    //     revealed_msg_indices.clone(),
    // )
    // .unwrap();

    // let chal = SignatureMessage::from_msg_hash(&pok.to_bytes());

    // let proof = pok.gen_proof(&chal).unwrap();

    // let mut revealed_msgs = HashMap::new();
    // for i in &revealed_msg_indices {
    //     revealed_msgs.insert(i.clone(), msgs[*i].clone());
    // }
    // assert!(proof.verify(&gpk, revealed_msgs.clone(), &chal).unwrap());
}
