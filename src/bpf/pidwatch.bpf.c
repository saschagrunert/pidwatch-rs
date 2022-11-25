#include "vmlinux.h"

#include "pidwatch.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event _event = {};  // dummy instance for skeleton to generate definition

const volatile struct {
    u32 pid;  // PID to filter
} cfg = {};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} ringbuf SEC(".maps");

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void * ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != cfg.pid) {
        return 0;
    }

    struct task_struct * task = bpf_get_current_task();
    int read_exit_code = BPF_CORE_READ(task, exit_code);

    struct event event = {
        .exit_code = read_exit_code >> 8,
        .signaled = read_exit_code & 0xff,
    };

    int * value = bpf_ringbuf_reserve(&ringbuf, sizeof(struct event), 0);
    if (value) {
        memcpy(value, &event, sizeof(struct event));
        bpf_ringbuf_submit(value, 0);
    }

    return 0;
}

SEC("kprobe/oom_kill_process")
int kprobe__oom_kill_process(struct pt_regs * ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != cfg.pid) {
        return 0;
    }

    struct event event = {.oom = true};

    int * value = bpf_ringbuf_reserve(&ringbuf, sizeof(struct event), 0);
    if (value) {
        memcpy(value, &event, sizeof(struct event));
        bpf_ringbuf_submit(value, 0);
    }

    return 0;
}
