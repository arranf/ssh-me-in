#![warn(clippy::all)]

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;

use anyhow::*;
use chrono::Utc;
use directories::UserDirs;
use external_ip;
use log::{debug, info, LevelFilter};
use quick_xml::de::from_str;
use rusoto_core::{region::Region, RusotoError};
use rusoto_ec2::{
    AuthorizeSecurityGroupIngressError, AuthorizeSecurityGroupIngressRequest, Ec2, Ec2Client,
    IpPermission, IpRange,
};
use structopt::StructOpt;
use tokio::fs::read_to_string;
use whoami::{host, user, username};

mod unknown_error;
use unknown_error::UnknownError;
mod options;
use options::Options;

static VALID_DESCRIPTION_CHARACTERS: [char; 22] = [
    '.', ' ', '_', '-', ':', '/', '(', ')', '#', ',', '@', '[', ']', '+', '=', '&', ';', '{', '}',
    '!', '$', '*',
];
#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::from_args();
    env_logger::builder()
        // Disable errors from child modules
        .filter(None, LevelFilter::Off)
        // Filter current module at verbosity passed in option
        .filter(
            Some(module_path!()),
            options
                .verbosity
                .log_level()
                .map_or_else(|| LevelFilter::Off, |l| l.to_level_filter()),
        )
        .init();

    debug!("Options: {:?}", options);
    let security_groups = get_security_groups(&options.config).await?;
    debug!("Security Groups: {:?}", &security_groups);
    // TODO: SPINNER
    let ip_address = get_ip_address().await?;
    info!("IP Address: {}", &ip_address);
    // TODO: SPINNER

    let update_ip_results: Vec<Result<(), RusotoError<AuthorizeSecurityGroupIngressError>>> =
        update_ips(
            &ip_address,
            &security_groups,
            &options.region,
            options.dry_run,
        )
        .await?;

    handle_results(&update_ip_results, &security_groups);

    // This is here to silence warnings, in all cases handle_results will process::exit()
    Ok(())
}

/// Attempts to obtain a consensus choice on this machines external IP address.
async fn get_ip_address() -> Result<IpAddr> {
    let ip = external_ip::get_ip().await;
    ip.ok_or_else(|| anyhow!("Unable to obtain IP address"))
}

/// Attempts to either add to or update the ingress rules for the given security groups with the machine's current IP address.
async fn update_ips(
    ip_address: &IpAddr,
    security_group_ids: &[String],
    requested_region: &Option<String>,
    is_dry_run: bool,
) -> Result<Vec<Result<(), RusotoError<AuthorizeSecurityGroupIngressError>>>> {
    let region = match requested_region {
        Some(r) => Region::from_str(r.as_str())?,
        None => Region::default(),
    };
    info!("AWS Region: {:?}", &region);

    let ec2_client = Ec2Client::new(region);
    let machine_description: String = get_machine_description();
    let mut results: Vec<Result<(), RusotoError<AuthorizeSecurityGroupIngressError>>> = vec![];
    for security_group_id in security_group_ids {
        let req = create_auth_request(
            &security_group_id,
            &ip_address,
            &machine_description,
            is_dry_run,
        );
        results.push(ec2_client.authorize_security_group_ingress(req).await);
    }
    Ok(results)
}

/// Iterates over the results from the update operations, pretty prints them, and then exits with the correct exit code.
fn handle_results(
    results: &Vec<Result<(), RusotoError<AuthorizeSecurityGroupIngressError>>>,
    security_groups: &Vec<String>,
) {
    let is_error = results.iter().any(|r| r.is_err());
    for (i, result) in results.iter().enumerate() {
        let security_group: &str = &security_groups[i];
        match result {
            Err(r) => {
                // TODO: Move this error handling into a struct impl that takes the RusotoError, and then produces the correct error message for printing here
                match r {
                    RusotoError::Unknown(_) => {
                        // We get a nasty error which displays as XML error here, so we deserialize to get just the message out.
                        let unknown_error: Result<UnknownError, _> = from_str(&format!("{}", r));
                        match &unknown_error {
                            Ok(e) => {
                                println!("Error updating security group {}: {}", security_group, e)
                            }
                            Err(e) => println!("{}", e),
                        }
                    }
                    _ => println!("Error updating security group {}: {}", security_group, r),
                }
            }
            Ok(_) => println!("Succesfully updated security group {}", security_group),
        }
    }

    // Ensure errors are reported correctly to OS.
    match is_error {
        true => exit(1),
        false => exit(0),
    }
}

/// Attempts to obtain a list of security group ids from a known path.
async fn get_security_groups(directory: &Option<PathBuf>) -> Result<Vec<String>> {
    let config_location = directory
        .clone()
        .or_else(|| {
            if let Some(users_dir) = UserDirs::new() {
                return PathBuf::from_str(".ssh-me-in")
                    .ok()
                    .map(|relative_location| users_dir.home_dir().join(relative_location));
            }
            // Failed to get users home directory.
            None
        })
        .ok_or_else(|| anyhow!("Unable to identify config file location. Please explicitly pass the config file location in with the --config argument."))?;

    let path_exists = config_location.exists();
    debug!("Config Path: {:?}", &config_location);
    if !path_exists {
        return Err(anyhow!(
            "Config file does not exist. Please create a config file 'ssh-me' in your home directory or pass the config file location in with the --config argument."
        ));
    }

    let file_contents = read_to_string(config_location).await?;
    // TODO: Make portable (?)
    let security_groups: Vec<String> = file_contents
        .split('\n')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_owned())
        .collect();

    match security_groups.len() {
        0 => Err(anyhow!("No security groups found. Please specify security group ids on separate lines in your config file")),
        _ => Ok(security_groups)
    }
}

/// Creates a description to accompany the IP rule containing the user's name, machine name, and time.
/// The description is truncated to fit the description's max length of 255 characters and filtered to ensure all characters are valid.
fn get_machine_description() -> String {
    let mut user_identifier = user();
    if user_identifier.is_empty() {
        user_identifier = username();
    }
    user_identifier.truncate(80);

    let mut host = host();
    host.truncate(80);

    let description = format!(
        "{} on {} at {}",
        user_identifier,
        host,
        Utc::now().format("%Y-%m-%d %H:%M").to_string()
    );
    let santized_description: String = description
        .chars()
        .filter(|c: &char| c.is_alphanumeric() || VALID_DESCRIPTION_CHARACTERS.contains(c))
        .collect();
    debug!("Sanitized description is {}", santized_description);
    santized_description
}

/// Creates the request used to add the IP address to the security group ingress rules
fn create_auth_request(
    security_group_id: &str,
    ip_address: &IpAddr,
    description: &str,
    dry_run: bool,
) -> AuthorizeSecurityGroupIngressRequest {
    // It's 'idiomatic' using rusoto to create a mutable struct with defaults and the mutate the fields you need.
    let mut req = AuthorizeSecurityGroupIngressRequest::default();
    req.group_id = Some(security_group_id.to_owned());
    req.dry_run = Some(dry_run);

    // SSH access occurs on port 22 via TCP
    let mut ip_permission = IpPermission::default();
    ip_permission.ip_protocol = Some("tcp".to_string());
    ip_permission.from_port = Some(22);
    ip_permission.to_port = Some(22);

    let mut ip_range = IpRange::default();
    // The /32 suffix specifies a single IP address
    ip_range.cidr_ip = Some(format!("{}/32", ip_address.to_string()));

    ip_range.description = Some(description.to_owned());
    ip_permission.ip_ranges = Some(vec![ip_range]);
    req.ip_permissions = Some(vec![ip_permission]);
    req
}
