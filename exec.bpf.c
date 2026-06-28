#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256

struct event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[TASK_COMM_LEN];
    __u8  filename[MAX_FILENAME_LEN];
};

/* Force struct event into the .o's BTF. Harmless now; required later if you
   move to bpf2go with `-type event` so it can generate the Go struct for you. */
const struct event *unused __attribute__((unused));

/* The ring buffer. max_entries is the byte size of the ring (power of two,
   page-multiple) — NOT a count of events. 256 KB here. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    /* Reserve a slot. Returns a pointer INTO the ring (zero-copy) or NULL if
       the ring is full. If NULL, drop the event and move on — never block. */
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;

    /* CO-RE earning its keep: walk current->real_parent->tgid. Each arrow is a
       relocatable kernel-struct read that survives across kernel versions. */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    /* comm here is the LAUNCHER (e.g. bash) — exec hasn't swapped it yet. */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* execve's first arg is the target path, a userspace string pointer. */
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
    /* Make the event visible to userspace. After this, `e` is off-limits. */
    bpf_ringbuf_submit(e, 0);
    return 0;
}