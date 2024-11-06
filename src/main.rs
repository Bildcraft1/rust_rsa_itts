use colog;
use log::info;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_traits::cast::ToPrimitive;
use num_traits::{One, Zero};
use rand::thread_rng;
use std::io;

pub struct RSA {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
}

impl RSA {
    pub fn new(_key_size: usize) -> Self {
        let mut _rng = thread_rng();

        let p = _rng.gen_biguint(1024);
        let q = _rng.gen_biguint(1024);
        let n = &p * &q;

        let phi = (&p - BigUint::one()) * (&q - BigUint::one());
        let e = _rng.gen_biguint(1024);
        let d = mod_inverse(&e, &phi).unwrap();

        RSA { n, e, d }
    }

    pub fn encrypt(&self, message: &str) -> Vec<BigUint> {
        message
            .bytes()
            .map(|b| {
                let m = BigUint::from(b as u32);
                if m >= self.n {
                    panic!("Message too large for current key size");
                }
                m.modpow(&self.e, &self.n)
            })
            .collect()
    }

    pub fn decrypt(&self, encrypted: &[BigUint]) -> String {
        let decrypted: Vec<u8> = encrypted
            .iter()
            .map(|c| {
                let m = c.modpow(&self.d, &self.n);
                m.to_u8().unwrap()
            })
            .collect();

        String::from_utf8(decrypted).expect("Failed to decode UTF-8")
    }
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let mut t = BigInt::zero();
    let mut newt = BigInt::one();
    let mut r = m.to_bigint().unwrap();
    let mut newr = a.to_bigint().unwrap();

    while !newr.is_zero() {
        let quotient = &r / &newr;
        let (temp_t, temp_r) = (t.clone(), r.clone());
        t = newt.clone();
        r = newr.clone();
        newt = temp_t - &quotient * &newt;
        newr = temp_r - &quotient * &newr;
    }

    if r > BigInt::one() {
        return None;
    }

    while t < BigInt::zero() {
        t = t + &m.to_bigint().unwrap();
    }

    Some(t.to_biguint().unwrap())
}

fn main() {
    colog::init();
    info!("RSA Encryption/Decryption");
    info!("Enter a message to encrypt:");

    let rsa = RSA::new(1024); // Small key size for testing
    let mut message: String = "".to_string();
    match io::stdin().read_line(&mut message) {
        Ok(n) => match n {
            0 => info!("No input provided"),
            _ => info!("{} bytes read", n),
        },
        Err(error) => println!("error: {error}"),
    }

    info!("Original: {}", message);

    let encrypted = rsa.encrypt(&message);
    info!("Encrypted: {:?}", encrypted);

    let decrypted = rsa.decrypt(&encrypted);
    info!("Decrypted: {}", decrypted);
}
