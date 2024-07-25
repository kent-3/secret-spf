use eyre::Result;
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

const TRACE_ROOTDIR: &str = "/sys/kernel/debug/tracing";

pub struct SpfTracer {
    file: std::fs::File,
}

impl SpfTracer {
    pub fn new() -> Result<Self> {
        Self::write_file("trace", " ")?;
        Self::reset()?;

        let file = std::fs::File::open("/dev/null")?;
        Ok(Self { file })
    }

    pub async fn start(&mut self, receiver: broadcast::Receiver<()>) -> Result<()> {
        Self::make_instance_dir()?;

        Self::write_file("instances/spf/trace_clock", "mono_raw")?;
        Self::write_file("kprobe_events", "p:spf_eldu sgx_encl_eldu addr=+0(%si)")?;
        Self::append_file("kprobe_events", "p:spf_ewb sgx_encl_ewb addr=+0(%si)")?;
        Self::write_file("instances/spf/events/kprobes/spf_eldu/enable", "1")?;
        Self::write_file("instances/spf/events/kprobes/spf_ewb/enable", "1")?;

        // NOTE: for testing only
        // Self::append_file("kprobe_events", "p:exit_event do_exit")?;
        // Self::write_file("instances/spf/events/kprobes/exit_event/enable", "1")?;

        let path = Path::new(TRACE_ROOTDIR).join("instances/spf/trace_pipe");
        self.file = std::fs::File::open(&path)?;

        self.run(receiver).await?;

        Ok(())
    }

    pub fn stop() -> Result<()> {
        Self::reset()
    }

    fn reset() -> Result<()> {
        let path = Path::new(TRACE_ROOTDIR).join("instances/spf/events/kprobes/spf_eldu/enable");
        if path.exists() && path.is_file() {
            trace!("Disabling {}", &path.display());
            Self::write_file("instances/spf/events/kprobes/spf_eldu/enable", "0")?;
        }

        let path = Path::new(TRACE_ROOTDIR).join("instances/spf/events/kprobes/spf_ewb/enable");
        if path.exists() && path.is_file() {
            trace!("Disabling {}", &path.display());
            Self::write_file("instances/spf/events/kprobes/spf_ewb/enable", "0")?;
        }

        let path = Path::new(TRACE_ROOTDIR).join("instances/spf/tracing_on");
        if path.exists() && path.is_file() {
            trace!("Disabling {}", &path.display());
            Self::write_file("instances/spf/tracing_on", "0")?;
        }

        Self::write_file("tracing_on", "0")?;

        let path = Path::new(TRACE_ROOTDIR).join("instances/spf");
        if path.exists() && path.is_dir() {
            trace!("Removing /sys/kernel/debug/tracing/instances/spf...");
            std::fs::remove_dir("/sys/kernel/debug/tracing/instances/spf")?;
        }

        Self::write_file("current_tracer", "nop")?;
        Self::write_file("kprobe_events", " ")?;
        Self::write_file("set_ftrace_filter", " ")?;
        Self::write_file("set_ftrace_notrace", " ")?;
        Self::write_file("set_graph_function", " ")?;
        Self::write_file("set_graph_notrace", " ")?;

        Ok(())
    }

    async fn read_fd(&self, mut stop_rx: broadcast::Receiver<()>) -> Result<()> {
        let file = File::from_std(self.file.try_clone()?);
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut last_timestamp: Option<f64> = None;
        let time_threshold = 0.1;

        let log_path = Path::new("spf.log");
        let mut log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;
        log_file.set_permissions(std::fs::Permissions::from_mode(0o666))?;

        let canonical_path = std::fs::canonicalize(log_path)?;
        info!("Writing to log file {}", canonical_path.display());

        debug!("Reading trace_pipe...");
        loop {
            tokio::select! {
                line = lines.next_line() => {
                    match line {
                        Ok(Some(l)) => {
                            if let Some(timestamp) = extract_timestamp(&l) {
                                if let Some(last) = last_timestamp {
                                    if timestamp - last > time_threshold {
                                        let break_str = "\n";
                                        println!("{}", break_str);
                                        // writeln!(log_file, "{}", break_str)?;
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
                    break;
                }
            }
            trace!("loop: reading trace_pipe");
            // sleep(Duration::from_millis(1000)).await;
        }

        trace!("Exited read trace_pipe loop");
        Ok(())
    }

    async fn run(&self, stop_rx: broadcast::Receiver<()>) -> Result<()> {
        // TODO: put the tokio::select! part here, isolate the file processing in the other fn
        self.read_fd(stop_rx).await
    }

    fn make_instance_dir() -> Result<()> {
        let path = Path::new(TRACE_ROOTDIR).join("instances/spf");

        if path.exists() && path.is_dir() {
            trace!("Removing /sys/kernel/debug/tracing/instances/spf...");
            std::fs::remove_dir(&path)?;
        }

        trace!("Creating /sys/kernel/debug/tracing/instances/spf...");
        std::fs::DirBuilder::new().mode(0o766).create(&path)?;

        Ok(())
    }

    fn write_file(relpath: &str, val: &str) -> Result<()> {
        trace!("Writing {} to file {}...", val, relpath);
        let path = Path::new(TRACE_ROOTDIR).join(relpath);
        Self::do_write(path, val, false)
    }

    fn append_file(relpath: &str, val: &str) -> Result<()> {
        trace!("Appending {} to file {}...", val, relpath);
        let path = Path::new(TRACE_ROOTDIR).join(relpath);
        Self::do_write(path, val, true)
    }

    fn do_write(path: impl AsRef<Path>, val: &str, append: bool) -> Result<()> {
        std::fs::OpenOptions::new()
            .write(true)
            .append(append)
            .truncate(!append)
            .open(&path)?
            .write_all(val.as_bytes())
            .map_err(Into::into)
    }
}

fn extract_timestamp(line: &str) -> Option<f64> {
    let timestamp_regex = regex::Regex::new(r"\s(\d+\.\d+):").unwrap();
    timestamp_regex
        .captures(line)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().parse().ok()))
        .flatten()
}
