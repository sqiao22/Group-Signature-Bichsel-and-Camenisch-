extern crate amcl_wrapper;
extern crate zmix;
extern crate ursa;


use amcl_wrapper::group_elem::GroupElement;
use zmix::signatures::prelude::*;
use zmix::signatures::ps::prelude::*;


use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

use amcl_wrapper::extension_field_gt::GT;



use std::mem::transmute;

// use amcl_wrapper::ECCurve::big::BIG;

// use ursa::cl::issuer::Issuer;
// use ursa::cl::prover::Prover;
// use ursa::cl::verifier::Verifier;
// use ursa::cl::*;
// use std::time::{Duration, Instant};

//Create gpk, gmsk
pub fn GSetup (count_msgs: usize, label: &[u8])->(Gpk, Gmsk){
    println!("GSetup Start.........");
    let (gpk, gmsk) = For_GSetup(count_msgs, label);
    // print_type_of(&gpk);
    println!("GSetup Successful!");
    (gpk, gmsk)
}

//Create usk[i] and upk[i] for Gjoin 
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

//Need to convert G1 into number so it can be signed
pub fn hashing(s: DefaultHasher,message: amcl_wrapper::group_elem_g1::G1)->u64{
    let mut hasher = s.clone();
    message.hash(&mut hasher);
    hasher.finish()
}
// Need this so tow can be a FieldElementVector
pub fn sign_usk_i(s:DefaultHasher,tow:amcl_wrapper::group_elem_g1::G1,usk_i:SecretKey, upk_i:PublicKey)->Signature{
    let tow_hash=hashing(s.clone(),tow.clone()).to_be_bytes();
    // println!("{:?}", tow_hash);
    let oneMess = FieldElement::from_msg_hash(&tow_hash);
    let mut msg=FieldElementVector::new(0);
    // println!("{:?}", tow_hash % 20 );
    msg.push(oneMess);
    // println!("{:?}", msg);
    Signature::new(msg.as_slice(), &usk_i, &upk_i).unwrap()

}
// Check sign_usk_i signature
pub fn verify_usk_i(signature_usk_i: Signature,s:DefaultHasher,tow:amcl_wrapper::group_elem_g1::G1, upk_i:PublicKey)->bool{

    let tow_hash=hashing(s.clone(),tow.clone()).to_be_bytes();
    let oneMess = FieldElement::from_msg_hash(&tow_hash);
    let mut msg=FieldElementVector::new(0);
    msg.push(oneMess);
    // println!("{:?}", msg);
    let check=signature_usk_i.verify(msg.as_slice(),&upk_i).unwrap();
    check
}

//using interactive sigma protocol, when ski is the only thing given
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

//Without this the requester cannot sign and if there’s no signature then there’s nothing to verify
pub fn GJoin (i: usize, gpk: Gpk,gmsk: Gmsk, upk_i:PublicKey ,usk_i:SecretKey)->((usize,amcl_wrapper::group_elem_g1::G1,Signature,amcl_wrapper::group_elem_g2::G2,DefaultHasher), (amcl_wrapper::field_elem::FieldElement, (amcl_wrapper::group_elem_g1::G1, amcl_wrapper::group_elem_g1::G1), amcl_wrapper::extension_field_gt::GT)){
    println!("GJoin Start.........");
    //USER generates a secret key,τ, τ_tidle, η and send τ, τ_tidle and η
    println!("USER create ski, τ, τ_tidle and η and send τ, τ_tidle and η");
    let ski= FieldElement::random();
    let tow=&gpk.g * &ski;
    let tow_tilde= &gpk.Y_tilde * &ski;
    let mut hash_saved = DefaultHasher::new();
    let n =sign_usk_i(hash_saved.clone(), tow.clone(), usk_i.clone(), upk_i.clone());
    // let m =sign_usk_i(s.clone(), tow.clone(), usk_i.clone(), upk_i.clone());
    // let check1=verify_usk_i(n.clone(),s.clone(), tow.clone(),upk_i.clone());
    // let check2=verify_usk_i(m.clone(),s.clone(), tow.clone(),upk_i.clone());
    // println!("{:?}",check1);
    // println!("{:?}",check2);
    

    //GROUP MANAGER tests e(τ, Y_tilde) =e(g, τ_tilde)
    let res = GT::ate_pairing(&tow, &gpk.Y_tilde);
    let res2 = GT::ate_pairing(&gpk.g, &tow_tilde);
    println!("GROUP MANAGER tests e(τ, Y_tilde) =e(g, τ_tilde): {:?}", res==res2);
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
    //(g^x·(τ)^y)^u=g^x^u·(τ)^y^u IS this true?????
    let sigma2=&gpk.g * &gmsk.x * &u + &tow * &gmsk.y * &u;
    let sigma=(sigma1.clone(),sigma2.clone());


    println!("Group Manager Stores i,τ,η,τ_tilde and hash");
    //Group Manager Store (i,τ,η,τ_tilde) need to add s for hasher
    let secret_register=(i,tow,n,tow_tilde,hash_saved);

    println!("USER Stores ski,σ,e(σ1,Y_tilde)");
    //User Store (ski,σ,e(σ1,Y_tilde))
    let gsk_i=(ski,sigma,GT::ate_pairing(&sigma1,&gpk.Y_tilde));

    println!("GJoin Successful!");

    (secret_register,gsk_i)

}

//Hash tuple of messy G1,GT,str
pub fn H1(s:DefaultHasher,message:(amcl_wrapper::group_elem_g1::G1,
    amcl_wrapper::group_elem_g1::G1,
    amcl_wrapper::extension_field_gt::GT,&str))->u64{
    let mut hasher = s.clone();
    message.hash(&mut hasher);
    hasher.finish()
}

// Requester sign message with ski[i] and outputs signature and message
pub fn GSign(gsk_i:(amcl_wrapper::field_elem::FieldElement, 
    (amcl_wrapper::group_elem_g1::G1, 
        amcl_wrapper::group_elem_g1::G1),
    amcl_wrapper::extension_field_gt::GT),msg:&'static  str)->(
    (amcl_wrapper::group_elem_g1::G1, 
    amcl_wrapper::group_elem_g1::G1, 
    amcl_wrapper::field_elem::FieldElement, 
    amcl_wrapper::field_elem::FieldElement), 
    DefaultHasher,&'static  str){
    println!("GSign Start.........");
    // let msg="test_message";
    let ski=gsk_i.0;
    let sigma1=gsk_i.1.0;
    let sigma2=gsk_i.1.1;
    let e=gsk_i.2;

    //USER Create t and  computing  (σ′1,σ′2)←(σt1,σt2)
    let t = FieldElement::random();
    let sigma1_dash=sigma1 * &t;
    let sigma2_dash=sigma2 * &t;

    //USER create a  signature  of  knowledge  ofski.
    let k = FieldElement::random();
    // e(σ′1, Y_tilde)^k←e(σ1, Y_tilde)^k·t
    let e_tok_tot=e.pow(&k).pow(&t);

    //Please note code need to convert (σ′1,σ′2,e(σ1, Y_tilde)^k·t,m) to a hash u8 so this tuple can be converted into Fieldelement form using from_msg_hash
    let mut hash_saved = DefaultHasher::new();
    let number = H1(hash_saved.clone(),(sigma1_dash.clone(),sigma2_dash.clone(),e_tok_tot.clone(),msg)).to_be_bytes();
    // let number = let bytes: [u8; 4] = unsafe { transmute(H1((sigma1_dash.clone(),sigma2_dash.clone(),e_tok_tot.clone(),msg)).to_be()) };
    // let number2 = H1(ss.clone(),(sigma1_dash.clone(),sigma2_dash.clone(),e_tok_tot.clone(),msg)).to_be_bytes();
    // println!("{:?}", number);

    //c needs to be a fieldElement
    let c = FieldElement::from_msg_hash(&number);
    // //make sure hash consistent
    // let c2 = FieldElement::from_msg_hash(&number);
    // println!("{:?}", c);
    // println!("{:?}", c2);

    // USER Compute s←k+c·ski
    let s = &k + &c * &ski;

    //Output outputs (σ′1,σ′2,c,s) and m
    let mu=(sigma1_dash,sigma2_dash,c,s);
    println!("GSign Successful!");

    (mu,hash_saved.clone(), msg)

}

//Verify Requester Group ID
pub fn GVerify(gpk: Gpk,mu:(amcl_wrapper::group_elem_g1::G1, 
    amcl_wrapper::group_elem_g1::G1, 
    amcl_wrapper::field_elem::FieldElement, 
    amcl_wrapper::field_elem::FieldElement), 
    hash_for_tuple:DefaultHasher,msg:&'static  str)->bool{

    println!("GVerify Start.........");
    let sigma1_dash=mu.0;
    let sigma2_dash=mu.1;
    let c=mu.2;
    let c1=c.clone();
    let s=mu.3;

    // Verifier computes R←(e(σ1^-1, X_tilde)·e(σ2, g_tilde))−c·e(σs1, Y_tilde) 
    // let b = &-c; //also works, but slower?
    let b =&c.negation();
    //Assuming (e(g1,g2)*e(h1,h2))^-c ==e(g1^-c,g2)*e(h1^-c,h2)
    let R =GT::ate_multi_pairing(vec![(&(-&sigma1_dash).scalar_mul_variable_time(b),&gpk.X_tilde),
        (&sigma2_dash.scalar_mul_variable_time(b),&gpk.g_tilde),
        (&sigma1_dash.scalar_mul_variable_time(&s),&gpk.Y_tilde)]);
    let number = H1(hash_for_tuple.clone(),(sigma1_dash.clone(),sigma2_dash.clone(),R.clone(),msg)).to_be_bytes();
    let c2 = FieldElement::from_msg_hash(&number);
    // Verify that c=H(σ1,σ2,R,m);
    println!("Does this Verify: {:?}", c1==c2);

    println!("GVerify Successful!");
    c1==c2


    // a=e(σ1^-1, X_tilde)·e(σ2, g_tilde))^−c

    // let a = GT::ate_2_pairing(&(-&sigma1_dash),&gpk.X_tilde,&sigma2_dash,&gpk.g_tilde).pow(&-c);
    // // b=e(σ1^s, Y_tilde)=e(σ1, Y_tilde)^s;
    // // let b = GT::ate_pairing(&sigma1_dash,&gpk.Y_tilde).pow(&s);
    // let b=GT::ate_pairing(&sigma1_dash.scalar_mul_variable_time(&s),&gpk.Y_tilde);
    // // R=a·b
    // // let R = a*b;

    // let b = &-c;


    // let e_vector = Vec::new();

    // let sig1_inverse=-&sigma1_dash;
    // e_vector.push((sig1_inverse,gpk.X_tilde));

    // e_vector.push((sigma2_dash,gpk.g_tilde));

    // let sig1_to_s=sigma1_dash.scalar_mul_variable_time(&s);
    // e_vector.push((sig1_to_s,gpk.Y_tilde));


    // let a1 = GT::ate_2_pairing(&(-&sigma1_dash),&gpk.X_tilde,&sigma2_dash,&gpk.g_tilde).pow(&s);
    // let a2 = GT::ate_2_pairing(&(-&sigma1_dash).scalar_mul_variable_time(&s),&gpk.X_tilde,&sigma2_dash.scalar_mul_variable_time(&s),&gpk.g_tilde);
    // println!("{:?}", a1==a2);

    //e(g1,g2)^s=e(g1^s,g2);
    // let b2=GT::ate_pairing(&sigma1_dash.scalar_mul_variable_time(&s),&gpk.Y_tilde);
    // println!("{:?}", b==b2);



    // let test1=GT::ate_pairing(&(-&sigma1_dash),&gpk.Y_tilde);
    // let test1_1=GT::ate_pairing(&sigma1_dash,&gpk.Y_tilde);
    // let test2=GT::ate_pairing(&sigma1_dash,&gpk.Y_tilde).inverse();

    // println!("{:?}", test1==test2);
    // println!("{:?}", test1_1==test2);

    // let r=ate_pairing();

}

//Used as last resort to find identity, Note need to know gpk since need g.tilde and X_tilde
pub fn GOpen(gpk: Gpk,gmsk_array: Vec<(usize,amcl_wrapper::group_elem_g1::G1,Signature,amcl_wrapper::group_elem_g2::G2,DefaultHasher)>, mu:(amcl_wrapper::group_elem_g1::G1, 
    amcl_wrapper::group_elem_g1::G1, 
    amcl_wrapper::field_elem::FieldElement, 
    amcl_wrapper::field_elem::FieldElement), 
    hash_for_tuple:DefaultHasher,msg:&'static  str)->(){

    let sigma1_dash=mu.0;
    let sigma2_dash=mu.1;
    let c=mu.2;
    let s=mu.3;
    // let mut true_tow_tilde: amcl_wrapper::group_elem_g2::G2;
    // let mut true_identity: (usize,amcl_wrapper::group_elem_g1::G1,Signature);

    //loop to find the user
    for gmsk in gmsk_array{
        let idenity_id= gmsk.0;
        let tow = gmsk.1;
        let n = gmsk.2;
        let tow_tilde = gmsk.3;
        let hash_saved = gmsk.4;

        //check e(σ2, g_tilde)·e(σ1, X_tilde)^−1=e(σ1, τ_tilde)
        if GT::ate_2_pairing(&sigma2_dash,&gpk.g_tilde,&(-&sigma1_dash),&gpk.X_tilde)==GT::ate_pairing(&sigma1_dash,&tow_tilde){
            println!("The identity is User {:?}", idenity_id);
            let true_tow_tilde=tow_tilde;
            let true_identity=(idenity_id,tow,n);

            //Proof of knowledge of τ_tilde
            //GM informs all to chanellege it's knowledge of τ_tilde
            //Verifer generates r and A
            let r = FieldElement::random();
            let cha = &gpk.g*&r;
            //Verifer sends cha to Proofer/GM, GM calculates rsp=e(A,τ_tilde)
            let rsp = GT::ate_pairing(&cha,&true_tow_tilde);
            //GM sends rsp to Verifer
            //Verifer calculates e(τ,Y_tilde)^r and check if rsp=e(τ,Y_tilde)^r
            println!("Proof of knowledge of τ_tilde {:?}", rsp==GT::ate_pairing(&true_identity.1,&gpk.Y_tilde).pow(&r));


        }
    }

}

#[test]
fn test_scenario_1() {
 //Vec<(usize,amcl_wrapper::group_elem_g1::G1,Signature,amcl_wrapper::group_elem_g2::G2,DefaultHasher)>
    let mut gmsk_array=Vec::new();
    //Group Created
    //number of messages used to generate pk and sk
    let count_msgs = 1;
    let label="test".as_bytes();
    let (gpk, gmsk) = GSetup(count_msgs,label);

    // User A Created
    let (upk_1, usk_1)=PKIJoin(count_msgs,label);
    let user_id=1;
    let (secret_register_1,gsk_1) = GJoin (user_id,gpk.clone(),gmsk.clone(), upk_1,usk_1);
    //Store A idenity in secret GM array
    gmsk_array.push(secret_register_1.clone());


    // User B Created
    let (upk_2, usk_2)=PKIJoin(count_msgs,label);
    let user_id=2;
    let (secret_register_2,gsk_2) = GJoin (user_id,gpk.clone(),gmsk.clone(), upk_2,usk_2);
    //Store B idenity in secret GM array
    gmsk_array.push(secret_register_2.clone());


    //User A signs for message
    let (mu_1,hash_for_tuple_1, msg_1)= GSign(gsk_1.clone(),"I require 10 boeing 747");
    let verified_signature_1=GVerify(gpk.clone(),mu_1.clone(),hash_for_tuple_1.clone(), msg_1.clone());

    //User B signs for message
    let (mu_2,hash_for_tuple_2, msg_2)= GSign(gsk_2.clone(),"I require 5 boeing 747");
    let verified_signature_2=GVerify(gpk.clone(),mu_2.clone(),hash_for_tuple_2.clone(), msg_2.clone());


    // who signed mu_1,hash_for_tuple_1,msg_1?
    println!("Who signed this? {:?}", msg_1.clone());
    GOpen(gpk.clone(),gmsk_array.clone(),mu_1.clone(),hash_for_tuple_1.clone(),msg_1.clone());
    // who signed mu_2,hash_for_tuple_2,msg_2?
    println!("Who signed this? {:?}", msg_2.clone());
    GOpen(gpk.clone(),gmsk_array.clone(),mu_2.clone(),hash_for_tuple_2.clone(),msg_2.clone());




}
