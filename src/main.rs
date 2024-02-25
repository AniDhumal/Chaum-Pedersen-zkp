use num_bigint::{BigUint, RandBigInt};

//x^y mod p
pub fn exponentiate(n: &BigUint, exp: &BigUint, p: &BigUint) -> BigUint {
    n.modpow(exp, p)
}

// for s= k - cx mod q
pub fn solve(k: &BigUint, c: &BigUint, x: &BigUint, q: &BigUint) -> BigUint {
    if *k >= c * x {
        (k - c * x).modpow(&BigUint::from(1u32), q)
    } else {
        // -a mod b = b-a mod b
        (q - (c * x - k)).modpow(&BigUint::from(1u32), q)
    }
}

// r1 = alpha^s * y1^c
// r2 = beta^s * y2^c
pub fn verify(
    r1: &BigUint,
    r2: &BigUint,
    y1: &BigUint,
    y2: &BigUint,
    alpha: &BigUint,
    beta: &BigUint,
    c: &BigUint,
    s: &BigUint,
    p: &BigUint,
) -> bool {
    let con1 = *r1 == (alpha.modpow(s, p) * y1.modpow(c, p)).modpow(&BigUint::from(1u32), p);
    let con2 = *r2 == (beta.modpow(s, p) * y2.modpow(c, p)).modpow(&BigUint::from(1u32), p);
    con1 && con2
}

pub fn generate_random(limit: &BigUint) {
    let mut rng = rand::thread_rng();
    let rand_num = rng.gen_biguint_below(limit);
    println!("{}", rand_num);
}
fn main() {
    generate_random(&BigUint::from(u128::MAX))
}
