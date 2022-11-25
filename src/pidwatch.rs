use crate::bpf::{pidwatch_bss_types::event, PidwatchSkelBuilder};
use anyhow::{bail, format_err, Context, Result};
use libbpf_rs::RingBufferBuilder;
use libc::{rlimit, setrlimit};
use plain::Plain;

unsafe impl Plain for event {}

#[derive(Debug)]
pub struct PidWatch {
    pid: u32,
}

impl PidWatch {
    pub fn new(pid: u32) -> Self {
        Self { pid }
    }

    pub fn run(&self) -> Result<()> {
        let skel_builder = PidwatchSkelBuilder::default();

        Self::bump_memlock_rlimit().context("bump memlock rlimit")?;
        let mut open_skel = skel_builder.open().context("open skel builder")?;

        open_skel.rodata().cfg.pid = self.pid;

        let mut skel = open_skel.load().context("load skel")?;
        skel.attach().context("attach skel")?;

        let mut ring_buffer_builder = RingBufferBuilder::new();
        ring_buffer_builder
            .add(skel.maps_mut().ringbuf(), Self::callback)
            .context("add map to ringbuffer builder")?;

        let ring_buffer = ring_buffer_builder.build().context("build ringbuffer")?;

        loop {
            ring_buffer
                .poll(std::time::Duration::from_millis(100))
                .context("poll from ringbuffer")?;
        }
    }

    fn callback(data: &[u8]) -> i32 {
        if let Err(e) = Self::handle_event(data) {
            println!("Unable to handle event: {:#}", e);
            return 1;
        }
        0
    }

    fn handle_event(data: &[u8]) -> Result<()> {
        println!("Got event: {:?}", data);

        let mut event = event::default();
        plain::copy_from_bytes(&mut event, data)
            .map_err(|e| format_err!("data buffer was too short: {:?}", e))?;

        println!("Got exit code: {}", event.exit_code);
        println!("Got signaled code: {}", event.signaled);

        Ok(())
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
