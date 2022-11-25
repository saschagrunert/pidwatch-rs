use anyhow::{Context, Result};
use pidwatch::PidWatch;
use std::env;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let pid = args
        .get(1)
        .context("at least one PID argument required")?
        .parse::<u32>()
        .context("unable to parse PID")?;

    PidWatch::new(pid).run()
}
