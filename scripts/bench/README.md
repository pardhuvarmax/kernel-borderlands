# Sensor-overhead benchmark (plan item C3)

`microbench.c` times seven operations; `overhead.py` alternates three modes (`off`: `kbd` and `kb-sensor` stopped, `on`: shipped defaults, `bytes`: `on` plus `KB_BYTES_SENT=1`) over 5 rounds with the mode order rotated, and records the commit, binary hashes, kernel and CPU.

```bash
gcc -O2 -o microbench microbench.c
python3 overhead.py --ack-isolated --commit <sha of the build under test> --out result.json
```

Run it only on the isolated lab VM: it stops the protection for a while, and it needs passwordless `sudo`. It clears systemd's start limit before each service start (`kb-sensor.service` allows 5 starts per 2 minutes; the first attempt aborted on that) and verifies the restore at the end.

**What the numbers are.** `results/overhead-vm-20261110.json`: VirtualBox guest (6 vCPUs, kernel 6.8, Intel Core Ultra 9 275HX host), `kbd` `48aeeeb8…` (built from `554209a`), sensor `1f3654f3…`. Medians of five rounds; the min..max across rounds is in the JSON. They are **not comparable** with the host table on the project site: different kernel, virtualised, and a different set of operations (the harness behind the site's numbers was never committed). The site's "re-run pending" note stays until this is run on the host.

| Operation | off | on | on vs off | bytes | bytes vs off |
| --- | --- | --- | --- | --- | --- |
| null syscall | 70 ns | 153 ns | +118% | 155 ns | +121% |
| open + close | 897 ns | 1,285 ns | +43% | 1,274 ns | +42% |
| mmap + mprotect + munmap | 1,884 ns | 2,241 ns | +19% | 2,246 ns | +19% |
| TCP socket + connect + close | 56.0 µs | 54.0 µs | -4% (noise) | 54.0 µs | -4% (noise) |
| UDP socket + connect + close | 2,619 ns | 3,190 ns | +22% | 3,115 ns | +19% |
| send 128 B (TCP, connected) | 300 ns | 376 ns | +26% | 464 ns | +55% |
| fork + exec (`/bin/true`) | 232 µs | 259 µs | +12% | 271 µs | +17% |

Reading: the sensor adds roughly 80 ns to every syscall in this guest. The optional byte counter adds about 88 ns per `send` on top (the `on` and `bytes` ranges across rounds do not overlap, 344-383 vs 447-508 ns) and shows nothing measurable elsewhere. The TCP connect row varies by more than the effect (off ranged 53.9-65.6 µs). Not measured: `make -j4` and `sysbench cpu` from the site table (no harness), resident memory, and the effect of a sustained event stream on `kbd`.
