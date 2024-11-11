use colog;
use log::info;
use num_bigint::BigUint;
use num_primes::Generator;
use num_traits::cast::ToPrimitive;
use num_traits::One;
use std::io;

pub struct RSA {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
}

impl RSA {
    pub fn new(key_size: usize) -> Self {
        // Generate two random primes of key_size/2 bits each
        let p = Generator::new_prime(key_size / 2);
        let q = Generator::new_prime(key_size / 2);

        // Convert num-primes::BigUint to num-bigint::BigUint
        let p_bigint = num_bigint::BigUint::parse_bytes(p.to_string().as_bytes(), 10).unwrap();
        let q_bigint = num_bigint::BigUint::parse_bytes(q.to_string().as_bytes(), 10).unwrap();

        let n = &p_bigint * &q_bigint;

        let phi =
            (&p_bigint - num_bigint::BigUint::one()) * (&q_bigint - num_bigint::BigUint::one());

        let e = num_bigint::BigUint::from(65537u32);

        // Calculate private key
        let d = BigUint::modinv(&e, &phi)
            .expect("Failed to compute modular inverse - e and phi must be coprime");

        info!("Generated RSA key pair of {} bits", key_size);
        info!("Public key (n,e): ({}, {})", n, e);
        info!("Private key (n,d): ({}, {})", n, d);

        RSA { n, e, d }
    }

    pub fn encrypt(&self, message: &str) -> Vec<BigUint> {
        message
            .trim() // Remove newline
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
                m.to_u8().expect("Decrypted value too large for u8")
            })
            .collect();

        String::from_utf8(decrypted).expect("Failed to decode UTF-8")
    }
}

fn main() {
    colog::init();
    info!("RSA Encryption/Decryption");
    info!("Enter a message to encrypt:");

    let mut message: String = "".to_string();
    match io::stdin().read_line(&mut message) {
        Ok(n) => match n {
            0 => info!("No input provided"),
            _ => info!("{} bytes read", n),
        },
        Err(error) => println!("error: {error}"),
    }

    let mut rsa_size: String = "".to_string();

    info!("Enter the size of the RSA key pair (in bits):");
    match io::stdin().read_line(&mut rsa_size) {
        Ok(n) => match n {
            0 => info!("No input provided"),
            _ => info!("{} bytes read", n),
        },
        Err(error) => println!("error: {error}"),
    }

    let rsa = RSA::new(rsa_size.trim().parse().unwrap());

    info!("Original: {}", message.trim());

    let encrypted = rsa.encrypt(&message);
    info!("Encrypted: {:?}", encrypted);

    let decrypted = rsa.decrypt(&encrypted);
    info!("Decrypted: {}", decrypted);
}
