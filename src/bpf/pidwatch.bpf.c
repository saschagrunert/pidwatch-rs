#include "vmlinux.h"
#include "pidwatch.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile struct {
    u32 pid; // PID to filter
} cfg = {};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096); // one page
} ringbuf SEC(".maps");

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void * ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (cfg.pid && pid != cfg.pid) {
        return 0;
    }

    struct task_struct * task = bpf_get_current_task();
    int read_exit_code = BPF_CORE_READ(task, exit_code);

    int * error_code = bpf_ringbuf_reserve(&ringbuf, sizeof(int), 0);
    if (error_code) {
        *error_code = read_exit_code >> 8;
        bpf_ringbuf_submit(error_code, 0);
    }

    return 0;
}
