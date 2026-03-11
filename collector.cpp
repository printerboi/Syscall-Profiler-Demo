#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "syscall_trace.skel.h"

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <unistd.h>

#include <memory>
#include <unordered_map>
#include <vector>

#include "RAPLReader.h"
#include "Domain.h"

/**
 * Signal handlers to terminate upon sigint
 */
static volatile sig_atomic_t stop_flag = 0;
static void on_sigint(int) { stop_flag = 1; }

/**
 * Event struct to handle syscall events
 */
struct evt {
    uint32_t tid;
    uint32_t id;   // syscall id for enter/exit, unused for switch
    uint8_t  type; // 0 enter, 1 exit, 2 switch_out, 3 switch_in
};

/**
 * Per-TID inflight state (supports sched_switch gating)
 */
struct Inflight {
    uint32_t syscall_id = 0;
    double   start_energy = 0.0;  // valid only while "running" segment is active
    bool     in_syscall = false;  // between sys_enter and sys_exit
    bool     running   = false;   // currently on CPU segment we are measuring
};

// Maximum id of syscalls we want to profile. Only necessary to allocate enough memory
static constexpr uint32_t MAX_SYSCALL = 1024;

// Data structures to save recorded values
static std::unordered_map<uint32_t, Inflight> inflight;
static std::vector<double>   energy_per_syscall(MAX_SYSCALL, 0.0);
static std::vector<uint64_t> count_per_syscall (MAX_SYSCALL, 0);

/**
 * Helper: add energy delta for a running segment and stop the segment.
 * Safe if called only when inf.running==true.
 */
static inline void stop_segment_and_accumulate(Inflight& inf) {
    const double endEng = RaplReader::readEnergy(CPU_DOMAIN);
    const double dE = endEng - inf.start_energy;

    if (inf.syscall_id < MAX_SYSCALL) {
        energy_per_syscall[inf.syscall_id] += dE;
    }
    inf.running = false;
}

/**
 * Helper: start a new running segment (after sys_enter or after switch_in while still in syscall)
 */
static inline void start_segment(Inflight& inf) {
    inf.start_energy = RaplReader::readEnergy(CPU_DOMAIN);
    inf.running = true;
}

/**
 * Event handler that will be called for syscall enter/exit and sched_switch gating
 * @param data Data inserted into the syscall
 * @param data_sz Size of the corresponding data
 * @return Returns 0
 */
static int handle_event(void*, void* data, size_t data_sz) {
    if (data_sz < sizeof(evt)) return 0;

    const auto* e = static_cast<const evt*>(data);

    // Ensure we have a state entry for this TID (also for switch events)
    auto& inf = inflight[e->tid]; // default-constructs if missing

    switch (e->type) {
        case 0: { // sys_enter
            if (e->id >= MAX_SYSCALL) {
                inf = Inflight{};
                return 0;
            }

            inf.syscall_id = e->id;
            inf.in_syscall = true;

            // At sys_enter we are on CPU, start measuring immediately
            start_segment(inf);
            break;
        }

        case 2: { // switch_out (prev_tid)
            // If the thread is switched out while still inside a syscall,
            // stop measuring so we do not measure sleep time.
            if (inf.in_syscall && inf.running) {
                stop_segment_and_accumulate(inf);
            }
            break;
        }

        case 3: { // switch_in (next_tid)
            // If the thread is scheduled back in and still inside the same syscall,
            // restart measuring for the next on-CPU segment.
            if (inf.in_syscall && !inf.running) {
                start_segment(inf);
            }
            break;
        }

        case 1: { // sys_exit
            // Finish the last on-CPU segment
            if (inf.in_syscall && inf.running) {
                stop_segment_and_accumulate(inf);
            }

            // Count one syscall completion
            if (inf.in_syscall && inf.syscall_id < MAX_SYSCALL) {
                count_per_syscall[inf.syscall_id] += 1;
            }

            // Clear state for this TID to avoid trash.
            inflight.erase(e->tid);
            break;
        }

        default:
            break;
    }

    return 0;
}

// Custom deleters so we don't forget cleanup
struct RingBufDeleter {
    void operator()(ring_buffer* rb) const { ring_buffer__free(rb); }
};
struct SkelDeleter {
    void operator()(syscall_trace_bpf* skel) const { syscall_trace_bpf__destroy(skel); }
};

/**
 * TGID ignore mapper to handle syscalls from this tool. Otherwise, we would cause an infinite loop of syscalls.
 * @param skel BPF Skeleton
 * @param tgid_to_ignore Task ID to ignore
 * @return
 */
static int set_ignore_tgid_map(syscall_trace_bpf* skel, uint32_t tgid_to_ignore) {
    // ignore_tgid_map is a 1-element BPF_MAP_TYPE_ARRAY with key=0 -> value=tgid
    uint32_t key = 0;
    uint32_t val = tgid_to_ignore;

    int map_fd = bpf_map__fd(skel->maps.ignore_tgid_map);
    if (map_fd < 0) {
        std::fprintf(stderr, "failed to get ignore_tgid_map fd\n");
        return -1;
    }

    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
        std::fprintf(stderr,
                     "bpf_map_update_elem(ignore_tgid_map) failed: %s\n",
                     std::strerror(errno));
        return -1;
    }
    return 0;
}

int main() {
    // Register signal handler
    std::signal(SIGINT,  on_sigint);
    std::signal(SIGTERM, on_sigint);

    // Define bpf skeleton and parameters
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    std::unique_ptr<syscall_trace_bpf, SkelDeleter> skel(syscall_trace_bpf__open());
    if (!skel) {
        std::fprintf(stderr, "failed to open skel\n");
        return 1;
    }

    if (syscall_trace_bpf__load(skel.get())) {
        std::fprintf(stderr, "failed to load bpf\n");
        return 1;
    }

    // Ignore our own process so RaplReader's open/read/close syscalls
    // don't generate events and cause feedback loops.
    if (set_ignore_tgid_map(skel.get(), static_cast<uint32_t>(getpid())) != 0) {
        return 1;
    }

    if (syscall_trace_bpf__attach(skel.get())) {
        std::fprintf(stderr, "failed to attach bpf\n");
        return 1;
    }

    std::unique_ptr<ring_buffer, RingBufDeleter> rb(
        ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, nullptr, nullptr)
    );
    if (!rb) {
        std::fprintf(stderr, "ring_buffer__new failed\n");
        return 1;
    }

    std::fprintf(stderr, "Profiling syscalls... Ctrl-C to stop.\n");

    while (!stop_flag) {
        int err = ring_buffer__poll(rb.get(), 100 /* ms */);
        if (stop_flag) break;
        if (err == -EINTR) continue;
        if (err < 0) {
            std::fprintf(stderr, "poll error: %d\n", err);
            break;
        }
    }

    std::printf("syscall_id,avg_energy_per_call,total_energy,count\n");
    for (uint32_t i = 0; i < MAX_SYSCALL; ++i) {
        if (count_per_syscall[i] == 0) continue;
        const double total = energy_per_syscall[i];
        const double avg   = total / static_cast<double>(count_per_syscall[i]);
        std::printf("%u,%.12f,%.12f,%lu\n", i, avg, total, count_per_syscall[i]);
    }

    return 0;
}
