#![deny(missing_docs, unused_crate_dependencies)]
#![feature(let_chains)]

//! Atomicals mining manager.

mod cli;
use cli::Cli;

mod electrumx;
mod engine;
mod util;
mod wallet;

mod prelude {
	pub use anyhow::{Error, Result};
}
use prelude::*;

// crates.io
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
	color_eyre::install().unwrap();
	tracing_subscriber::fmt::init();

	Cli::parse().run().await?;

	Ok(())
}
