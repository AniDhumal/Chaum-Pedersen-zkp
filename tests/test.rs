use chaum_pedersen_zkp::constants;
use chaum_pedersen_zkp::ZKP;
use num_bigint::BigUint;

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_random_1024_bits() {
        let p = BigUint::from_bytes_be(&hex::decode(constants::P).unwrap());
        let q = BigUint::from_bytes_be(&hex::decode(constants::Q).unwrap());
        let alpha = BigUint::from_bytes_be(&hex::decode(constants::ALPHA).unwrap());
        let beta = alpha.modpow(&ZKP::generate_random(&q), &p);
        let zkp = ZKP {
            p: p.clone(),
            q: q.clone(),
            alpha: alpha.clone(),
            beta: beta.clone(),
        };
        //secret
        let x = ZKP::generate_random(&q);
        // random number k
        let k = ZKP::generate_random(&q);
        let y1 = ZKP::exponentiate(&alpha, &x, &p);
        let y2 = ZKP::exponentiate(&beta, &x, &p);
        let r1 = ZKP::exponentiate(&alpha, &k, &p);
        let r2 = ZKP::exponentiate(&beta, &k, &p);
        //challenge
        let c = ZKP::generate_random(&q);

        println!("x: {}", x);
        println!("k: {}", k);
        println!("c: {}", c);

        //solution
        let s = zkp.solve(&k, &c, &x);
        //verification
        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);

        assert!(result);
    }
}
