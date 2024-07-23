use eyre::Result;
use futures::stream::StreamExt;
use signal_hook::{consts::signal::*, low_level::exit};
use signal_hook_tokio::Signals;
use tokio::{
    sync::broadcast,
    time::{sleep, Duration},
};
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::EnvFilter;

mod tracer;
use tracer::SpfTracer;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Create an EnvFilter with a default level of "info" if RUST_LOG is not set
    let filter = EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .without_time()
        .with_file(false)
        .with_line_number(false)
        .with_target(false)
        .init();

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    let signals = Signals::new(&[SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;
    let signal_handle = signals.handle();
    let signals_task = tokio::spawn(handle_signals(signals, shutdown_tx));

    let mut tracer = SpfTracer::new()?;

    info!("Starting...");
    tracer.start(shutdown_rx).await?;
    info!("Exiting...");

    // Terminate the signal stream.
    signal_handle.close();
    signals_task.await?;

    Ok(())
}

async fn handle_signals(mut signals: Signals, shutdown_tx: broadcast::Sender<()>) {
    while let Some(signal) = signals.next().await {
        match signal {
            SIGHUP => {
                // Handle SIGHUP differently if needed
                info!("Received SIGHUP signal");
            }
            SIGTERM | SIGINT | SIGQUIT => {
                shutdown_tx.send(()).unwrap();
                sleep(Duration::from_secs(1)).await;
                match SpfTracer::stop() {
                    Ok(_) => {
                        info!("Goodbye");
                        exit(0)
                    }
                    Err(error) => {
                        warn!("Could not cleanup tracing files: {error}");
                        warn!("Perform manual cleanup with `sudo rmdir /sys/kernel/debug/tracing/instances/spf`");
                        info!("Goodbye");
                        exit(1)
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}
