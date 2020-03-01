use clap_verbosity_flag::Verbosity;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "authorize-me",
    about = "A tool for adding your IP to the AWS security groups to allow remote work."
)]
pub struct Options {
    /// Activate dry run mode for testing your permissions
    #[structopt(short, long)]
    pub dry_run: bool,

    /// AWS Region to target by default it matches the region from AWS_DEFAULT_REGION environment variable, the AWS_REGION environment variable, and then your AWS config in that order of prescedence.
    /// Malformed input will fallback to us-east-1.
    #[structopt(short, long)]
    pub region: Option<String>,

    /// The path to the config file which contains line separated security group ids. Defaults to $HOME/authorize-me.
    #[structopt(short, long, parse(from_os_str))]
    pub config: Option<PathBuf>,

    #[structopt(flatten)]
    pub verbosity: Verbosity,
}
