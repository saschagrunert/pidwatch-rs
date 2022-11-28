use anyhow::{Context, Result};
use pidwatch::{Event, PidWatch};
use std::env;
use tracing::{error, info};
use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, prelude::*};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let pid = args
        .get(1)
        .context("at least one PID argument required")?
        .parse::<u32>()
        .context("unable to parse PID")?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_line_number(true)
                .with_filter(LevelFilter::DEBUG),
        )
        .try_init()?;

    let mut rx = PidWatch::new(pid).run().await?;

    info!("Receiving events");
    match rx.recv().await.context("receive event")? {
        Event::Err(e) => error!("{:#}", e),
        Event::Exit(exit) => info!("Got exit event: {:?}", exit),
    }

    info!("Done");
    Ok(())
}
