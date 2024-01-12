use std::time::Instant;

use argon2::{Argon2, Params, password_hash::SaltString, PasswordHasher};
use rand::distributions::{Alphanumeric, DistString};

use crate::DIFFICULTY_BYTES;

pub fn run(salt: SaltString, difficulty: f64, params: Params) {
    // kinda jank but works
    let prefix = format!(
        "COCK-UNBLOCK-{}-",
        Alphanumeric
            .sample_string(&mut rand::thread_rng(), 8)
            .to_uppercase()
    );

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut current = 1_u64;
    let mut timing = Instant::now();

    loop {
        let password = format!("{}{}", prefix, current);
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();

        let raw_hash = password_hash.hash.unwrap();
        let hasharr = raw_hash.as_bytes();
        let mut hashnum = 0_f64;
        for i in 0..DIFFICULTY_BYTES {
            hashnum += 256_f64.powf((DIFFICULTY_BYTES - i - 1) as f64)
                * ((0xff & hasharr[i as usize]) as f64);
        }
        if hashnum < difficulty {
            println!("SOLUTION FOUND");
            println!("{}", password);
            println!("{}", password_hash);
            break;
        }
        current += 1;
        if timing.elapsed().as_millis() > 1000 {
            println!("{}", current);
            timing = Instant::now();
        }
    }
}