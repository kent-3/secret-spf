use eyre::Result;
use futures::stream::StreamExt;
use regex::Regex;
use signal_hook::{consts::signal::*, low_level::exit};
use signal_hook_tokio::Signals;
use systemd::journal;
use tokio::{
    sync::{broadcast, mpsc},
    task,
    time::{sleep, Duration},
};
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::EnvFilter;

mod tracer;
use tracer::SpfTracer;

/// Polls for new Journal entries every [Duration]. Provide a [Regex] to further filter the
/// log outputs.
fn journal_thread(
    tx: mpsc::UnboundedSender<String>,
    sleep_duration: Duration,
    pattern: Option<Regex>,
) {
    let mut journal = journal::OpenOptions::default()
        .open()
        .expect("Failed to open journal");

    journal
        .match_add("SYSLOG_IDENTIFIER", "secretd")
        .expect("Failed to add match");
    journal
        .seek_tail()
        .expect("Failed to seek to the end of the journal");
    journal
        .previous()
        .expect("Failed to move to the previous journal entry");

    loop {
        if let Ok(Some(entry)) = journal.next_entry() {
            if let Some(message) = entry.get("MESSAGE") {
                let should_send = pattern
                    .as_ref()
                    .map(|re| re.is_match(message))
                    .unwrap_or(true);

                if should_send && tx.send(message.to_string()).is_err() {
                    break;
                }
            }
        } else {
            // Add a short sleep to reduce CPU usage
            std::thread::sleep(sleep_duration);
        }
    }
}

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

    let signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;
    let signal_handle = signals.handle();
    let signals_task = tokio::spawn(handle_signals(signals, shutdown_tx));

    // Channel must be unbounded because the sender is in a non-async context
    let (log_tx, mut log_rx) = mpsc::unbounded_channel();

    let sleep_duration = Duration::from_millis(1000);
    let re = Regex::new(r"executed block").expect("Failed to compile regex");

    // Create a non-async task to check the Journal for new entries
    debug!("Spawning journal thread...");
    task::spawn_blocking(move || {
        journal_thread(log_tx, sleep_duration, Some(re));
    });

    // Create an async task to handle log messages
    debug!("Spawning log writer thread...");
    task::spawn(async move {
        while let Some(log) = log_rx.recv().await {
            // Perform desired action with the log message
            println!("{}", log);
            // Example: Write to another program or API
            // send_to_api(log).await;
        }
        trace!("loop: log handler")
    });

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
