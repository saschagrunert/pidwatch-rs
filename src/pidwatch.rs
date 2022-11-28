use crate::bpf::{pidwatch_bss_types::event, PidwatchSkelBuilder};
use anyhow::{bail, format_err, Context, Error, Result};
use libbpf_rs::RingBufferBuilder;
use libc::{rlimit, setrlimit};
use plain::Plain;
use std::time::Duration;
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task,
};
use tracing::{debug, debug_span, error, Instrument};

unsafe impl Plain for event {}

#[derive(Debug)]
/// An event send by the `PidWatch` instance.
pub enum Event {
    /// An exit event containing actual data.
    Exit(Exit),

    /// An error indicating that the PID watcher failed.
    Err(Error),
}

#[derive(Debug)]
/// Available exit types for processes.
pub enum Exit {
    /// A process exited normally.
    Exited(i32),

    /// A signal stopped the process.
    Signaled(u32),

    /// The process got killed because it ran out of memory.
    OOMKilled,
}

#[derive(Debug)]
/// The main PID watching type of this module.
pub struct PidWatch {
    pid: u32,
}

impl PidWatch {
    /// Create a new PidWatch instance.
    pub fn new(pid: u32) -> Self {
        debug!("Initializing new PID watcher for PID: {pid}");
        Self { pid }
    }

    /// Run the PID watcher
    pub async fn run(&self) -> Result<UnboundedReceiver<Event>> {
        debug!("Running PID watcher");
        let skel_builder = PidwatchSkelBuilder::default();

        Self::bump_memlock_rlimit().context("bump memlock rlimit")?;
        let mut open_skel = skel_builder.open().context("open skel builder")?;

        open_skel.rodata().cfg.pid = self.pid;

        let mut skel = open_skel.load().context("load skel")?;
        skel.attach().context("attach skel")?;

        let (tx, rx) = mpsc::unbounded_channel();
        let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();

        task::spawn(
            async move {
                let mut ringbuffer_builder = RingBufferBuilder::new();
                if let Err(e) = ringbuffer_builder
                    .add(skel.maps_mut().ringbuf(), |data| {
                        Self::callback(data, &tx, &stop_tx)
                    })
                    .context("add ringbuffer callback")
                {
                    tx.send(Event::Err(e)).expect("send error event");
                    return;
                }

                match ringbuffer_builder.build().context("build ringbuffer") {
                    Err(e) => tx.send(Event::Err(e)).expect("send error event"),
                    Ok(ringbuffer) => loop {
                        if stop_rx.try_recv().is_ok() {
                            debug!("Stopping ringbuffer loop");
                            break;
                        }

                        if let Err(e) = ringbuffer
                            .poll(Duration::from_secs(1))
                            .context("unable to poll from ringbuffer")
                        {
                            error!("{:#}", e);
                            tx.send(Event::Err(e)).expect("send error event");
                        }
                    },
                };
            }
            .instrument(debug_span!("ringbuffer")),
        );

        Ok(rx)
    }

    fn callback(data: &[u8], tx: &UnboundedSender<Event>, stop_tx: &UnboundedSender<()>) -> i32 {
        if let Err(e) = Self::handle_event(data, tx, stop_tx) {
            error!("Unable to handle event: {:#}", e);
            tx.send(Event::Err(e)).expect("send error event");
        }
        1
    }

    fn handle_event(
        data: &[u8],
        tx: &UnboundedSender<Event>,
        stop_tx: &UnboundedSender<()>,
    ) -> Result<()> {
        let mut event = event::default();
        plain::copy_from_bytes(&mut event, data)
            .map_err(|e| format_err!("data buffer was too short: {:?}", e))?;

        debug!("Sending data event");

        let exit = match (event.exit_code, event.signaled_exit_code, event.oom_killed) {
            (_, _, true) => Exit::OOMKilled,
            (0, s, false) if s != 0 => Exit::Signaled(s),
            (e, 0, false) => Exit::Exited(e),
            _ => bail!("invalid event combination: {:?}", event),
        };

        tx.send(Event::Exit(exit)).context("send data event")?;
        stop_tx.send(()).context("send stop message")
    }

    fn bump_memlock_rlimit() -> Result<()> {
        let rlimit = rlimit {
            rlim_cur: 128 << 20,
            rlim_max: 128 << 20,
        };

        if unsafe { setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
            bail!("failed to increase rlimit");
        }

        Ok(())
    }
}
