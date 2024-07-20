use eyre::Result;
use futures::stream::StreamExt;
use signal_hook::{consts::signal::*, low_level::exit};
use signal_hook_tokio::Signals;
use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::Path,
};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
    sync::broadcast,
    time::{sleep, Duration},
};
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};

async fn handle_signals(mut signals: Signals, shutdown_tx: broadcast::Sender<()>) {
    while let Some(signal) = signals.next().await {
        match signal {
            SIGHUP => {
                // Handle SIGHUP differently if needed
                info!("Received SIGHUP signal");
                // For example, reload configuration here
                // reload_config().await?;
            }
            SIGTERM | SIGINT | SIGQUIT => {
                shutdown_tx.send(()).unwrap();
                sleep(Duration::from_secs(1)).await;
                match spf_tracer_stop() {
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

const TRACE_ROOTDIR: &str = "/sys/kernel/debug/tracing";

struct SpfTracer {
    pub file: File,
}

fn spf_tracer_do_write(path: impl AsRef<Path>, val: &str, append: bool) -> Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .append(append)
        .truncate(!append)
        .open(&path)?
        .write_all(val.as_bytes())
        .map_err(Into::into)
}

fn spf_tracer_write_file(relpath: &str, val: &str) -> Result<()> {
    trace!("Writing {} to file {}...", val, relpath);
    let path = Path::new(TRACE_ROOTDIR).join(relpath);
    spf_tracer_do_write(path, val, false)
}

fn spf_tracer_append_file(relpath: &str, val: &str) -> Result<()> {
    trace!("Appending {} to file {}...", val, relpath);
    let path = Path::new(TRACE_ROOTDIR).join(relpath);
    spf_tracer_do_write(path, val, true)
}

fn spf_tracer_reset() -> Result<()> {
    let path = Path::new(TRACE_ROOTDIR).join("instances/spf/events/kprobes/spf_eldu/enable");
    if path.exists() && path.is_file() {
        trace!("Disabling {}", &path.display());
        spf_tracer_write_file("instances/spf/events/kprobes/spf_eldu/enable", "0")?;
    }

    let path = Path::new(TRACE_ROOTDIR).join("instances/spf/events/kprobes/spf_ewb/enable");
    if path.exists() && path.is_file() {
        trace!("Disabling {}", &path.display());
        spf_tracer_write_file("instances/spf/events/kprobes/spf_ewb/enable", "0")?;
    }

    let path = Path::new(TRACE_ROOTDIR).join("instances/spf/tracing_on");
    if path.exists() && path.is_file() {
        trace!("Disabling {}", &path.display());
        spf_tracer_write_file("instances/spf/tracing_on", "0")?;
    }

    spf_tracer_write_file("tracing_on", "0")?;

    let path = Path::new(TRACE_ROOTDIR).join("instances/spf");
    if path.exists() && path.is_dir() {
        trace!("Removing /sys/kernel/debug/tracing/instances/spf...");
        std::fs::remove_dir("/sys/kernel/debug/tracing/instances/spf")?;
    }

    spf_tracer_write_file("current_tracer", "nop")?;
    spf_tracer_write_file("kprobe_events", " ")?;
    spf_tracer_write_file("set_ftrace_filter", " ")?;
    spf_tracer_write_file("set_ftrace_notrace", " ")?;
    spf_tracer_write_file("set_graph_function", " ")?;
    spf_tracer_write_file("set_graph_notrace", " ")?;

    Ok(())
}

fn spf_tracer_init() -> Result<()> {
    spf_tracer_write_file("trace", " ")?;
    spf_tracer_reset()?;
    Ok(())
}

async fn spf_tracer_read_fd(tracer: SpfTracer, mut stop_rx: broadcast::Receiver<()>) -> Result<()> {
    let reader = BufReader::new(tracer.file);
    let mut lines = reader.lines();
    let mut last_timestamp: Option<f64> = None;
    let time_threshold = 1.0;

    let log_path = Path::new("spf.log");
    let mut log_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(log_path)?;
    log_file.set_permissions(std::fs::Permissions::from_mode(0o666))?;

    let canonical_path = std::fs::canonicalize(log_path)?;
    info!("Writing to log file {}", canonical_path.display());

    trace!("Reading from file descriptor...");
    loop {
        tokio::select! {
            line = lines.next_line() => {
                match line {
                    Ok(Some(l)) => {
                        if let Some(timestamp) = extract_timestamp(&l) {
                            trace!(timestamp);
                            if let Some(last) = last_timestamp {
                                if timestamp - last > time_threshold {
                                    let break_str = "\n---\n";
                                    println!("{}", break_str);
                                    writeln!(log_file, "{}", break_str)?;
                                }
                            }
                            last_timestamp = Some(timestamp);
                        }
                        println!("{}", l);
                        writeln!(log_file, "{}", l)?;
                    }
                    Ok(None) => break,
                    Err(e) => {
                        error!("Error reading from trace_pipe: {:?}", e);
                        break;
                    }
                }
            },
            _ = stop_rx.recv() => {
                println!("");
                break;
            }
        }
    }

    trace!("Exited loop");
    Ok(())
}

fn extract_timestamp(line: &str) -> Option<f64> {
    let timestamp_regex = regex::Regex::new(r"\s(\d+\.\d+):").unwrap();
    timestamp_regex
        .captures(line)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().parse().ok()))
        .flatten()
}

async fn spf_tracer_runloop(tracer: SpfTracer, stop_rx: broadcast::Receiver<()>) -> Result<()> {
    spf_tracer_read_fd(tracer, stop_rx).await
}

async fn spf_tracer_create() -> Result<()> {
    spf_tracer_init()
}

fn spf_tracer_make_instance_dir() -> Result<()> {
    let path = Path::new(TRACE_ROOTDIR).join("instances/spf");

    if path.exists() && path.is_dir() {
        trace!("Removing /sys/kernel/debug/tracing/instances/spf...");
        std::fs::remove_dir(&path)?;
    }

    trace!("Creating /sys/kernel/debug/tracing/instances/spf...");
    std::fs::DirBuilder::new().mode(0o766).create(&path)?;

    Ok(())
}

async fn spf_tracer_start(receiver: broadcast::Receiver<()>) -> Result<()> {
    spf_tracer_make_instance_dir()?;

    spf_tracer_write_file("instances/spf/trace_clock", "mono_raw")?;
    spf_tracer_write_file("kprobe_events", "p:spf_eldu sgx_encl_eldu addr=+0(%si)")?;
    spf_tracer_append_file("kprobe_events", "p:spf_ewb sgx_encl_ewb addr=+0(%si)")?;
    spf_tracer_write_file("instances/spf/events/kprobes/spf_eldu/enable", "1")?;
    spf_tracer_write_file("instances/spf/events/kprobes/spf_ewb/enable", "1")?;

    // NOTE: for testing only
    // spf_tracer_append_file("kprobe_events", "p:exit_event do_exit")?;
    // spf_tracer_write_file("instances/spf/events/kprobes/exit_event/enable", "1")?;

    let path = Path::new(TRACE_ROOTDIR).join("instances/spf/trace_pipe");
    let file = File::open(&path).await?;
    let tracer = SpfTracer { file };

    spf_tracer_runloop(tracer, receiver).await?;

    Ok(())
}

fn spf_tracer_stop() -> Result<()> {
    spf_tracer_reset()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let filter = EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into());
    ::tracing_subscriber::fmt()
        .with_env_filter(filter)
        .without_time()
        .with_file(false)
        .with_line_number(false)
        .with_target(false)
        .init();

    let signals = Signals::new(&[SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;
    let signal_handle = signals.handle();

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    let signals_task = tokio::spawn(handle_signals(signals, shutdown_tx));

    spf_tracer_create().await?;

    info!("Starting...");
    spf_tracer_start(shutdown_rx).await?;
    info!("Exiting...");

    signal_handle.close();
    signals_task.await?;

    Ok(())
}
