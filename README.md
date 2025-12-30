# Syscall Profiler

This repository contains experimental code for a systemcall profiler, that uses linux bpf tools to hook
into syscall execution. The tool calculates the energy consumption via syscall starting and ending hooks.
Eventually this yields a mapping `Syscall -> Energy per Execution`

The resulting energy is averaged over all syscall executions.
After execution the resulting mapping is returned in a CSV format.

Currently, the only purpose of this tool and the repository is to demo the possibilites of measuring energy usage of syscalls.

## Building

Create the neccessary information for bptf tools once using:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

Compile the project using the following commands:
```bash
mkdir build
cd build
cmake ..
make
```

## Execution

Execute the tool with elevated rights. Otherwise neither the energy readings using RAPL, nor the bpftools dependency will work!
```bash
cd build
sudo ./collector
```

Stop the tool after a certain amount of time using STRG+C to receive the measured values.

### Example:

```csv
syscall_id,energy,count
0,0.042415585336,682
1,0.001008538639,544
3,0.000492704087,207
4,0.000000000000,5
5,0.000354566072,152
7,0.521179543661,886
8,0.000000000000,1
9,0.000000000000,3
11,0.000000000000,4
13,0.005655924479,12
14,0.000000000000,6
16,0.000198539646,87
17,0.000618816292,137
20,0.000623914931,360
21,0.000000000000,1
24,0.000450921697,14679
35,0.142467680432,21
38,0.000267561092,172
39,0.000297934322,177
...
```

## Known Issues

- The mapping is additive, we only add syscalls that have been executed at least once.
- The measurement method proposed by this tool does not handle syscalls that "wait" for a certain event differently than any other syscall. This leads to major distortion in the recorded values of some syscalls. 
Example: Image the `poll` syscall is executed 3 times and yields the recorded values `{1J, 400J, 2J}`. The second execution waits rather long for the respective file decriptor and therefore uses an extensive amount of energy, while the actual execution of `poll` itself is hidden by the timely overhead.
- Some syscalls are being executed 1 to 2 times, but yield `0 J` in energy readings.