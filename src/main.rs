// - STD
use std::io::{Write, Read};
use std::path::{PathBuf, Path};
use std::fs::{File, OpenOptions};
use std::process::exit;

// - modules
pub mod password;
mod constants;

// - re-export
pub(crate) use constants::*;

// - external
use clap::{
    Parser,
    Subcommand,
};
use rand::prelude::*;
use log::{debug, error, info, LevelFilter};

#[derive(Parser)]
#[clap(about, version, author, override_usage="{TOOL_NAME} <SUBCOMMAND> [OPTIONS]")]
struct Cli {

    /// The config file
    #[clap(short='f', long="password-file", global=true, required=false)]
    password_file: PathBuf,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sets the password to the password file. This will just generate a new argon2id (encoded) hash.
    #[clap(arg_required_else_help=true)]
    SetPassword {
        /// The mem-cost.
        #[clap(short='m', long="mem-cost")]
        mem_cost: Option<u32>,

        /// Number of iterations.
        #[clap(short='i', long="iterations")]
        iterations: Option<u32>,

        /// A salt value.
        #[clap(short='s', long="salt")]
        salt: Option<String>,

        /// Parallelism.
        #[clap(short='l', long="parallelism")]
        parallelism: Option<u32>,

        /// The password.
        #[clap(short='p', long="password", required=true)]
        password: String,

    },
    /// checks credentials and logs in
    #[clap(arg_required_else_help=true)]
    Connect {
        /// The password.
        #[clap(short='p', long="password", required=true)]
        password: String,

        /// The device nickname
        #[clap(short='n', long="nickname")]
        nickname: String,

        /// The product serial number
        #[clap(short='s', long="serialnumber")]
        sn: String,

        /// The vendor id
        #[clap(short='v', long="vendor-id")]
        vendor: String,

        /// The product id
        #[clap(short='P', long="product-id")]
        product: String,

        /// The client ip
        #[clap(short='I', long="client-ip")]
        ip: String,
    },

    /// disconnects from server
    #[clap(arg_required_else_help=true)]
    Disconnect {
        /// The device nickname
        #[clap(short='n', long="nickname")]
        nickname: String,

        /// The product serial number
        #[clap(short='s', long="serialnumber")]
        sn: String,

        /// The vendor id
        #[clap(short='v', long="vendor-id")]
        vendor: String,

        /// The product id
        #[clap(short='P', long="product-id")]
        product: String,

        /// The client ip
        #[clap(short='I', long="client-ip")]
        ip: String,
    },
}

fn main() {
    let args = Cli::parse();
    env_logger::builder()
    .format_timestamp_nanos()
    .filter_module(TOOL_NAME, LevelFilter::Debug)
    .init(); 

    match &args.command {
        Commands::SetPassword { .. } => {
            set_password(&args);
        },
        Commands::Connect { password, nickname, sn, vendor, product, ip } => {
            connect(&args.password_file, password, nickname.to_string(), sn.to_string(), vendor.to_string(), product.to_string(), ip.to_string());
        },
        Commands::Disconnect { nickname, sn, vendor, product, ip } => {
            disconnect(nickname.to_string(), sn.to_string(), vendor.to_string(), product.to_string(), ip.to_string());
        }
    }      
}


fn disconnect(nickname: String, sn: String, vendor: String, product: String, ip: String) {
    info!("DISCONNECTED {ip}: {nickname};{sn};{vendor}:{product}");
}

fn connect<C: AsRef<Path>, P: Into<String>>(password_file: C, password: P, nickname: String, sn: String, vendor: String, product: String, ip: String) {
    let password = password.into();
    let mut file = open_password_file(password_file.as_ref());
    let mut password_hash = String::new();
    if let Err(e) =  file.read_to_string(&mut password_hash) {
        error!("An error occurred while trying to read password file: {}: {e}", password_file.as_ref().display());
        exit(EXIT_STATUS_ERROR);
    };
    match password::verify_password_hash(&password_hash, &password) {
        Ok(true) => {
            info!("CONNECTED {ip}: {nickname};{sn};{vendor}:{product}");
            exit(EXIT_STATUS_SUCCESS)
        },
        Ok(false) => exit(EXIT_STATUS_ERROR),
        Err(e) => {
            error!("An error occurred while trying to verify password for {nickname}: {e}");
            exit(EXIT_STATUS_ERROR);
        }
    }
}

fn set_password(args: &Cli) {
    let pw_hash = match &args.command {
        Commands::SetPassword { mem_cost, iterations, salt, parallelism, password } => {
            let salt = match salt {
                Some(salt) => salt.clone(),
                None => { let mut rng = rand::thread_rng(); let salt: u64 = rng.gen(); salt.to_string() },
            };
            match password::hash_password_argon2(
                password, 
                salt.as_bytes(), 
                mem_cost.unwrap_or(ARGON_MEM_COST_RECOMMENDED),
                parallelism.unwrap_or(ARGON_LANES_RECOMMENDED),
                iterations.unwrap_or(ARGON_ITERATIONS_RECOMMENDED),
                DEFAULT_HASH_LENGTH) {
                Ok(pw) => pw,
                Err(e) => {
                    error!("An error occurred while trying to create the argon2 password hash.");
                    debug!("{e}");
                    exit(EXIT_STATUS_ERROR);
                }
            }
        },
        _ => unreachable!() 
    };

    let mut file = open_password_file(&args.password_file);
    if let Err(e) = file.write(pw_hash.as_bytes()) {
        error!("An error occurred while trying to write password hash to file: {}: {e}", args.password_file.display());
        exit(EXIT_STATUS_ERROR);
    }
}

fn open_password_file<C: AsRef<Path>>(password_file: C) -> File {
    match OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .create(true)
            .open(password_file.as_ref()) {
        Ok(file) => file,
        Err(e) => {
            error!("An error occurred while trying to open password_file {}: {e}", password_file.as_ref().display());
            exit(EXIT_STATUS_ERROR);
        }
    }
}