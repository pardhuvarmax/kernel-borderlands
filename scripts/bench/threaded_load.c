/*
 * Synthetic threaded workload for experiment E14 (thread coverage of the syscall sampler).
 *
 *   gcc -O2 -pthread -o threaded_load threaded_load.c
 *   ./threaded_load MODE THREADS SECONDS RATE OUT.json
 *
 *   MODE     threaded : THREADS worker threads each run one of four syscall mixes; the main thread only
 *                       sleeps (the shape of a server whose main thread is supervisory).
 *            single   : the main thread does the same total work, all four mixes round-robin (the control).
 *   RATE     work units per second per thread (a unit is 1-2 syscalls); the total is capped at 100k units/s.
 *
 * It counts every syscall it issues, per syscall number, separately for the main thread and for all threads,
 * and writes them to OUT.json so the sensor's view (the per-pid syscall counts map) can be compared with the
 * truth. It prints "READY <pid>" on stdout once it is running.
 *
 * Safe by construction: it only reads /dev/zero and /etc/os-release, writes one byte at a time to /dev/null,
 * stats "/", and issues getppid/getuid. No network, no file creation other than OUT.json.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define NR_MAX 512
#define BATCH 200

#ifndef SYS_newfstatat
#define SYS_newfstatat SYS_fstatat64
#endif

struct counts { uint64_t n[NR_MAX]; };

static struct counts main_counts;
static struct counts *all_counts;      /* per thread, merged at the end */
static int nthreads, seconds, rate, single_mode;
static uint64_t deadline_ns;

static uint64_t mono_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

static uint64_t wall_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_REALTIME, &t);
	return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

static inline long sc(struct counts *c, long nr, long a, long b, long d)
{
	if (nr >= 0 && nr < NR_MAX)
		c->n[nr]++;
	return syscall(nr, a, b, d);
}

struct ctx { struct counts *c; int zero_fd, null_fd; char hostname_path[32]; char root[2]; };

static void unit(struct ctx *x, int mix)
{
	char b = 0;
	struct stat st;
	switch (mix & 3) {
	case 0:
		sc(x->c, SYS_getppid, 0, 0, 0);
		break;
	case 1:
		sc(x->c, SYS_read, x->zero_fd, (long)&b, 1);
		sc(x->c, SYS_write, x->null_fd, (long)&b, 1);
		break;
	case 2: {
		long fd = sc(x->c, SYS_openat, AT_FDCWD, (long)x->hostname_path, O_RDONLY);
		if (fd >= 0)
			sc(x->c, SYS_close, fd, 0, 0);
		break;
	}
	default:
		sc(x->c, SYS_getuid, 0, 0, 0);
		syscall(SYS_newfstatat, AT_FDCWD, x->root, &st, 0);
		if (SYS_newfstatat < NR_MAX)
			x->c->n[SYS_newfstatat]++;
		break;
	}
}

static void init_ctx(struct ctx *x, struct counts *c)
{
	memset(x, 0, sizeof(*x));
	x->c = c;
	strcpy(x->hostname_path, "/etc/os-release");
	strcpy(x->root, "/");
	x->zero_fd = (int)sc(c, SYS_openat, AT_FDCWD, (long)"/dev/zero", O_RDONLY);
	x->null_fd = (int)sc(c, SYS_openat, AT_FDCWD, (long)"/dev/null", O_WRONLY);
}

/* Run units at `units_per_s` until the deadline; mixes selected by `pick`. */
static void pace_loop(struct ctx *x, double units_per_s, int fixed_mix)
{
	uint64_t t0 = mono_ns(), done = 0;
	struct timespec ts;
	while (mono_ns() < deadline_ns) {
		for (int i = 0; i < BATCH; i++, done++)
			unit(x, fixed_mix >= 0 ? fixed_mix : (int)(done & 3));
		double ahead = (double)done / units_per_s - (double)(mono_ns() - t0) / 1e9;
		if (ahead > 0.0005) {
			ts.tv_sec = (time_t)ahead;
			ts.tv_nsec = (long)((ahead - (double)ts.tv_sec) * 1e9);
			x->c->n[SYS_nanosleep]++;
			syscall(SYS_nanosleep, &ts, NULL);
		}
	}
}

static void *worker(void *arg)
{
	long id = (long)arg;
	struct ctx x;
	init_ctx(&x, &all_counts[id]);
	pace_loop(&x, (double)rate, (int)(id & 3));
	return NULL;
}

static void dump_counts(FILE *f, const char *name, const struct counts *c)
{
	fprintf(f, "\"%s\": {", name);
	int first = 1;
	for (int i = 0; i < NR_MAX; i++)
		if (c->n[i]) {
			fprintf(f, "%s\"%d\": %llu", first ? "" : ", ", i, (unsigned long long)c->n[i]);
			first = 0;
		}
	fprintf(f, "}");
}

int main(int argc, char **argv)
{
	if (argc != 6) {
		fprintf(stderr, "usage: %s single|threaded THREADS SECONDS RATE OUT.json\n", argv[0]);
		return 2;
	}
	single_mode = strcmp(argv[1], "single") == 0;
	nthreads = atoi(argv[2]);
	seconds = atoi(argv[3]);
	rate = atoi(argv[4]);
	if (nthreads < 1 || nthreads > 64 || seconds < 1 || seconds > 120 || rate < 1 || (long)rate * nthreads > 100000) {
		fprintf(stderr, "refusing: threads 1-64, seconds 1-120, total rate <= 100000 units/s\n");
		return 2;
	}
	all_counts = calloc((size_t)nthreads, sizeof(struct counts));
	printf("READY %d\n", (int)getpid());
	fflush(stdout);
	uint64_t w0 = wall_ns();
	deadline_ns = mono_ns() + (uint64_t)seconds * 1000000000ull;

	struct ctx mx;
	init_ctx(&mx, &main_counts);
	if (single_mode) {
		pace_loop(&mx, (double)rate * nthreads, -1);
	} else {
		pthread_t *th = calloc((size_t)nthreads, sizeof(pthread_t));
		for (long i = 0; i < nthreads; i++)
			pthread_create(&th[i], NULL, worker, (void *)i);
		struct timespec ts = {0, 100 * 1000 * 1000};
		while (mono_ns() < deadline_ns) {      /* supervisory main thread */
			main_counts.n[SYS_nanosleep]++;
			syscall(SYS_nanosleep, &ts, NULL);
		}
		for (int i = 0; i < nthreads; i++)
			pthread_join(th[i], NULL);
	}
	uint64_t w1 = wall_ns();

	struct counts total = main_counts;
	for (int t = 0; t < nthreads; t++)
		for (int i = 0; i < NR_MAX; i++)
			total.n[i] += all_counts[t].n[i];
	uint64_t tm = 0, ta = 0;
	for (int i = 0; i < NR_MAX; i++) {
		tm += main_counts.n[i];
		ta += total.n[i];
	}
	FILE *f = fopen(argv[5], "w");
	if (!f)
		return 1;
	fprintf(f, "{\"pid\": %d, \"mode\": \"%s\", \"threads\": %d, \"seconds\": %d, \"rate_per_thread\": %d, "
		"\"start_wall_ns\": %llu, \"end_wall_ns\": %llu, \"total_all\": %llu, \"total_main\": %llu, ",
		(int)getpid(), single_mode ? "single" : "threaded", nthreads, seconds, rate,
		(unsigned long long)w0, (unsigned long long)w1, (unsigned long long)ta, (unsigned long long)tm);
	dump_counts(f, "all_counts", &total);
	fprintf(f, ", ");
	dump_counts(f, "main_counts", &main_counts);
	fprintf(f, "}\n");
	fclose(f);
	return 0;
}
