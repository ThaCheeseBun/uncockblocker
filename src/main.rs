mod multi;
mod single;

use clap::Parser;
use argon2::password_hash::SaltString;
use base64ct::{Base64, Encoding};

pub const DIFFICULTY_BYTES: u32 = 4;
const HASH_LENGTH: usize = 32;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Run multi-threaded (kinda sketch rn)
    #[arg(short, long, default_value_t = false)]
    mt: bool,

    /// Input challenge from cock.li
    input: String,
}

fn main() {
    let cli = Cli::parse();

    let split: Vec<&str> = cli.input.split(":").collect();

    let difficulty_raw = split[4].parse::<f64>().unwrap();
    let difficulty =
        256_f64.powf(DIFFICULTY_BYTES as f64 - (difficulty_raw.log2() / 256_f64.log2()));

    let salt_b64 = Base64::encode_string(split[3].as_bytes());
    let salt = SaltString::from_b64(salt_b64.as_str()).unwrap();

    let params = argon2::Params::new(
        split[1].parse::<u32>().unwrap(),
        split[2].parse::<u32>().unwrap(),
        1,
        Some(HASH_LENGTH),
    )
    .unwrap();

    if cli.mt {
        multi::run(salt, difficulty, params);
    } else {
        single::run(salt, difficulty, params);
    }
    
}
