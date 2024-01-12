use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use base64ct::{Base64, Encoding};
use rand::distributions::{Alphanumeric, DistString};
use std::env;
use rayon::prelude::*;

const DIFFICULTY_BYTES: u32 = 4;
const HASH_LENGTH: usize = 32;

#[derive(Debug)]
struct Thing {
    m_cost: u32, // mem
    t_cost: u32, // time
    p_cost: u32, // parallelism
    salt: String,
    difficulty: f64,
}

#[derive(Debug)]
struct Generator<'a> {
    difficulty: f64,
    prefix: String,
    salt: SaltString,
    ctx: Argon2<'a>,
    current: u64,
}
impl<'a> Generator<'a> {
    fn new(
        difficulty: f64,
        salt: String,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        output_len: Option<usize>,
    ) -> Generator<'a> {
        // kinda jank but works
        let prefix = format!(
            "COCK-UNBLOCK-{}-",
            Alphanumeric
                .sample_string(&mut rand::thread_rng(), 8)
                .to_uppercase()
        );
        // generate base64 and salt
        let salt_b64 = Base64::encode_string(salt.as_bytes());
        let salt = SaltString::from_b64(salt_b64.as_str()).unwrap();
        // generate parameters
        let params = argon2::Params::new(m_cost, t_cost, p_cost, output_len).unwrap();
        // create context
        let ctx = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        Generator {
            current: 0,
            difficulty,
            prefix,
            salt,
            ctx,
        }
    }
}
impl<'a> Iterator for Generator<'a> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        let password = format!("{}{}", self.prefix, self.current);
        let password_hash = self
            .ctx
            .hash_password(password.as_bytes(), &self.salt)
            .unwrap();

        let raw_hash = password_hash.hash.unwrap();
        let hasharr = raw_hash.as_bytes();
        let mut hashnum = 0_f64;
        for i in 0..DIFFICULTY_BYTES {
            hashnum += 256_f64.powf((DIFFICULTY_BYTES - i - 1) as f64)
                * ((0xff & hasharr[i as usize]) as f64);
        }
        if hashnum < self.difficulty {
            Some(password)
        } else {
            None
        }
    }
}

fn parse_challenge(chal: &String) -> Thing {
    let chal_split: Vec<&str> = chal.split(":").collect();

    let difficulty_raw = chal_split[4].parse::<f64>().unwrap();
    let difficulty =
        256_f64.powf(DIFFICULTY_BYTES as f64 - (difficulty_raw.log2() / 256_f64.log2()));

    Thing {
        m_cost: chal_split[1].parse::<u32>().unwrap(),
        t_cost: chal_split[2].parse::<u32>().unwrap(),
        p_cost: 1,
        salt: chal_split[3].to_owned(),
        difficulty,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 2 {
        eprintln!("Invalid amount of arguments.");
        return;
    }

    let arg = parse_challenge(&args[1]);
    println!("Params: {:#?}", arg);

    let wang = Generator::new(
        arg.difficulty,
        arg.salt,
        arg.m_cost,
        arg.t_cost,
        arg.p_cost,
        Some(HASH_LENGTH),
    );
    //println!("{:?}", wang.next());
    let wang2: Vec<String> = wang.par_bridge().collect();
    println!("{:?}", wang2);
}
