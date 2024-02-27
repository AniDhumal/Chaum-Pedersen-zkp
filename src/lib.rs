pub mod constants;

use num_bigint::{BigUint, RandBigInt};

pub struct ZKP {
    pub p: BigUint,
    pub q: BigUint,
    pub alpha: BigUint,
    pub beta: BigUint,
}

impl ZKP {
    //x^y mod p
    pub fn exponentiate(n: &BigUint, exp: &BigUint, p: &BigUint) -> BigUint {
        n.modpow(exp, p)
    }

    // for s= k - cx mod q
    pub fn solve(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        if *k >= c * x {
            (k - c * x).modpow(&BigUint::from(1u32), &self.q)
        } else {
            // -a mod b = b-a mod b
            &self.q - (c * x - k).modpow(&BigUint::from(1u32), &self.q)
        }
    }

    // r1 = alpha^s * y1^c
    // r2 = beta^s * y2^c
    pub fn verify(
        &self,
        r1: &BigUint,
        r2: &BigUint,
        y1: &BigUint,
        y2: &BigUint,
        c: &BigUint,
        s: &BigUint,
    ) -> bool {
        let con1 = *r1
            == (&self.alpha.modpow(s, &self.p) * y1.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);
        let con2 = *r2
            == (&self.beta.modpow(s, &self.p) * y2.modpow(c, &self.p))
                .modpow(&BigUint::from(1u32), &self.p);
        con1 && con2
    }

    pub fn generate_random(limit: &BigUint) -> BigUint {
        let mut rng = rand::thread_rng();
        let rand_num = rng.gen_biguint_below(limit);
        rand_num
    }
}
