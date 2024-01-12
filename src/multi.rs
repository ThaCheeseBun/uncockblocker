use std::thread;

use argon2::{password_hash::SaltString, Params, Argon2, PasswordHasher};
use crossbeam_channel::{unbounded, TryRecvError};
use rand::distributions::{Alphanumeric, DistString};

use crate::DIFFICULTY_BYTES;

pub fn run(salt: SaltString, difficulty: f64, params: Params) {
    let (tx1, rx1) = unbounded();
    let (tx2, rx2) = unbounded();

    let mut threads = vec![];
    for x in 0..num_cpus::get() {
        let cloned_salt = salt.clone();
        let cloned_params = params.clone();
        let (cloned_tx1, cloned_rx2) = (tx1.clone(), rx2.clone());

        threads.push(thread::spawn(move || {
            // kinda jank but works
            let prefix = format!(
                "COCK-UNBLOCK-{}-",
                Alphanumeric
                    .sample_string(&mut rand::thread_rng(), 8)
                    .to_uppercase()
            );
            let argon2 = Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                cloned_params,
            );
            let mut current = 1_u64;
            println!("running thread {}", &x);
            loop {
                let password = format!("{}{}", prefix, current);
                let password_hash = argon2.hash_password(password.as_bytes(), &cloned_salt).unwrap();
                let raw_hash = password_hash.hash.unwrap();
                let hasharr = raw_hash.as_bytes();
                let mut hashnum = 0_f64;
                for i in 0..DIFFICULTY_BYTES {
                    hashnum += 256_f64.powf((DIFFICULTY_BYTES - i - 1) as f64) * ((0xff & hasharr[i as usize]) as f64);
                }
                if hashnum < difficulty {
                    cloned_tx1.send(password).unwrap();
                }
                current += 1;
                match cloned_rx2.try_recv() {
                    Ok(_) | Err(TryRecvError::Disconnected) => {
                        println!("terminating thread {}", x);
                        break;
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }
        }));
    }

    for child in threads {
        let _ = child.join();
    }
    println!("{}", rx1.recv().unwrap());
    for _ in 0..num_cpus::get() {
        let _ = tx2.send(String::new());
    }
}