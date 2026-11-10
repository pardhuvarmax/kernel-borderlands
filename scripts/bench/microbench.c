/*
 * Per-operation cost microbenchmark for the sensor-overhead measurement (plan item C3).
 *
 *   gcc -O2 -o microbench microbench.c && taskset -c 2 ./microbench [batches]
 *
 * Prints one JSON object: the median over `batches` batches of ns per operation (fork+exec in us).
 * Operations: null syscall (getppid), open+close of /etc/hostname, socket+connect+close to a loopback
 * TCP listener (connect_ns) and to a loopback UDP address (udp_connect_ns, no handshake, the nearest
 * to a bare connect(2) call), send of 128 bytes on a connected loopback TCP socket (the path the optional
 * security_socket_sendmsg byte counter hooks), mmap+mprotect+munmap of one anonymous page, and
 * posix_spawn of /bin/true plus wait.
 *
 * Not the same as the operations on the project site (that harness was never committed): connect is
 * timed with socket() and close(), and the send case is new. Compare runs of THIS program only.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static double now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1e9 + t.tv_nsec;
}

static int cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;
	return (x > y) - (x < y);
}

static double median(double *v, int n)
{
	qsort(v, n, sizeof(double), cmp);
	return v[n / 2];
}

static double op_null(int n)
{
	double t = now_ns();
	for (int i = 0; i < n; i++)
		syscall(SYS_getppid);
	return (now_ns() - t) / n;
}

static double op_open(int n)
{
	double t = now_ns();
	for (int i = 0; i < n; i++)
		close(open("/etc/hostname", O_RDONLY));
	return (now_ns() - t) / n;
}

static double op_mmap(int n)
{
	double t = now_ns();
	for (int i = 0; i < n; i++) {
		void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		mprotect(p, 4096, PROT_READ);
		munmap(p, 4096);
	}
	return (now_ns() - t) / n;
}

static struct sockaddr_in srv_addr, sink_addr;

static double op_connect(int n)
{
	double t = now_ns();
	for (int i = 0; i < n; i++) {
		int s = socket(AF_INET, SOCK_STREAM, 0);
		connect(s, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
		close(s);
	}
	return (now_ns() - t) / n;
}

static double op_udp_connect(int n)
{
	double t = now_ns();
	for (int i = 0; i < n; i++) {
		int s = socket(AF_INET, SOCK_DGRAM, 0);
		connect(s, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
		close(s);
	}
	return (now_ns() - t) / n;
}

static double op_send(int n)
{
	char buf[128] = {0};
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(s, (struct sockaddr *)&sink_addr, sizeof(sink_addr)) < 0)
		return -1;
	double t = now_ns();
	for (int i = 0; i < n; i++)
		send(s, buf, sizeof(buf), 0);
	double r = (now_ns() - t) / n;
	close(s);
	return r;
}

static double op_spawn(int n)
{
	char *argv[] = {"/bin/true", NULL};
	double t = now_ns();
	for (int i = 0; i < n; i++) {
		pid_t p;
		if (posix_spawn(&p, "/bin/true", NULL, NULL, argv, environ) == 0)
			waitpid(p, NULL, 0);
	}
	return (now_ns() - t) / n / 1000.0;   /* microseconds */
}

/* Move the calling process off the CPUs the benchmark is pinned to (no-op when it is not pinned). */
static void leave_bench_cpu(void)
{
	cpu_set_t cur, other;
	CPU_ZERO(&other);
	if (sched_getaffinity(0, sizeof(cur), &cur) == 0 && CPU_COUNT(&cur) < CPU_SETSIZE) {
		long n = sysconf(_SC_NPROCESSORS_ONLN);
		for (long c = 0; c < n; c++)
			if (!CPU_ISSET(c, &cur))
				CPU_SET(c, &other);
		if (CPU_COUNT(&other) > 0)
			sched_setaffinity(0, sizeof(other), &other);
	}
}

/* Child A: accept and close at once. Child B: accept one connection and read until EOF. */
static void acceptor(int ls, int drain)
{
	char buf[65536];
	leave_bench_cpu();
	for (;;) {
		int c = accept(ls, NULL, NULL);
		if (c < 0)
			continue;
		if (drain)
			while (read(c, buf, sizeof(buf)) > 0)
				;
		close(c);
	}
}

static int listener(struct sockaddr_in *addr)
{
	int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(ls, (struct sockaddr *)addr, sizeof(*addr)) < 0 || listen(ls, 4096) < 0) {
		perror("listener");
		exit(1);
	}
	socklen_t l = sizeof(*addr);
	getsockname(ls, (struct sockaddr *)addr, &l);
	return ls;
}

int main(int argc, char **argv)
{
	int batches = argc > 1 ? atoi(argv[1]) : 7;
	if (batches < 1 || batches > 99)
		batches = 7;

	int ls_a = listener(&srv_addr), ls_b = listener(&sink_addr);
	pid_t acc_a = fork();
	if (acc_a == 0)
		acceptor(ls_a, 0);
	pid_t acc_b = fork();
	if (acc_b == 0)
		acceptor(ls_b, 1);

	struct { const char *name; double (*fn)(int); int n; } ops[] = {
		{"null_syscall_ns", op_null, 1000000},
		{"open_close_ns", op_open, 200000},
		{"mmap_mprotect_ns", op_mmap, 200000},
		{"connect_ns", op_connect, 20000},
		{"udp_connect_ns", op_udp_connect, 50000},
		{"send_128b_ns", op_send, 200000},
		{"fork_exec_us", op_spawn, 1500},
	};
	printf("{");
	for (size_t k = 0; k < sizeof(ops) / sizeof(ops[0]); k++) {
		double v[99];
		ops[k].fn(ops[k].n / 10);   /* warm-up */
		for (int b = 0; b < batches; b++)
			v[b] = ops[k].fn(ops[k].n);
		printf("%s\"%s\": %.1f", k ? ", " : "", ops[k].name, median(v, batches));
	}
	printf("}\n");
	kill(acc_a, SIGKILL);
	kill(acc_b, SIGKILL);
	return 0;
}
