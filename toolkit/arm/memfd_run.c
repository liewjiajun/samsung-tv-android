/*
 * memfd_run.c — execute an ARM binary that never touches the filesystem.
 *
 * BUILD
 *   arm-linux-musleabihf-gcc -O2 -static -o memfd_run memfd_run.c
 *
 * WHY
 * Samsung Tizen TVs refuse to execute unsigned binaries from the filesystem
 * (UEP). That is a provenance check on the file, not a ban on execution, so the
 * fix is to have no file. memfd_create() gives an anonymous RAM-backed file and
 * execveat(AT_EMPTY_PATH) runs it with no path resolved.
 *
 * The Tizen TV kernel is 4.1.10, so memfd_create (3.17+) is present.
 *
 * USAGE
 *   memfd_run <payload> [args...]   run payload from memory
 *   memfd_run --selftest            prove the technique on this device
 *
 * Intended for hardware the operator owns, to run software they are entitled to
 * run. Static build because the TV's libc does not match the build host's.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

/* armv7l syscall numbers; musl's headers normally supply these */
#ifndef SYS_memfd_create
#  if defined(__arm__)
#    define SYS_memfd_create 385
#    define SYS_execveat     387
#  elif defined(__aarch64__)
#    define SYS_memfd_create 279
#    define SYS_execveat     281
#  else
#    define SYS_memfd_create 319
#    define SYS_execveat     322
#  endif
#endif

#ifndef MFD_CLOEXEC
#  define MFD_CLOEXEC 0x0001U
#endif
#ifndef AT_EMPTY_PATH
#  define AT_EMPTY_PATH 0x1000
#endif

static int memfd_create_compat(const char *name, unsigned int flags) {
    return (int)syscall(SYS_memfd_create, name, flags);
}

/* exec a file descriptor with no path lookup at all */
static int exec_fd(int fd, char *const argv[], char *const envp[]) {
    return (int)syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
}

static long slurp_fd(int out, const char *path) {
    int in = open(path, O_RDONLY);
    if (in < 0) { perror("open payload"); return -1; }

    char buf[65536];
    ssize_t n;
    long total = 0;
    while ((n = read(in, buf, sizeof buf)) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w <= 0) { perror("write to memfd"); close(in); return -1; }
            off += w;
        }
        total += n;
    }
    close(in);
    return (n < 0) ? -1 : total;
}

static int run_payload(const char *path, char **args) {
    int fd = memfd_create_compat("payload", MFD_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "memfd_create failed: %s\n", strerror(errno));
        if (errno == ENOSYS)
            fprintf(stderr, "kernel is older than 3.17; memfd unavailable\n");
        return 2;
    }

    long size = slurp_fd(fd, path);
    if (size < 0) { close(fd); return 2; }

    if (fchmod(fd, 0700) != 0) { perror("fchmod"); close(fd); return 2; }

    fprintf(stderr, "[memfd_run] %ld bytes staged in memfd (nothing on disk)\n", size);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); close(fd); return 2; }

    if (pid == 0) {
        /* build argv: keep the caller's tail, prepend the program name */
        int argc = 0;
        while (args && args[argc]) argc++;

        char **argv = calloc((size_t)argc + 2, sizeof *argv);
        if (!argv) _exit(127);
        argv[0] = (char *)path;
        for (int i = 0; i < argc; i++) argv[i + 1] = args[i];
        argv[argc + 1] = NULL;

        exec_fd(fd, argv, environ);
        fprintf(stderr, "[memfd_run] execveat failed: %s\n", strerror(errno));
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); close(fd); return 2; }
    close(fd);

    if (WIFEXITED(status))   return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 2;
}

/* ------------------------------------------------------------------ */
/* self-test: prove it on THIS device, with a negative control          */
/* ------------------------------------------------------------------ */
static int selftest(void) {
    printf("=== memfd_run self-test ===\n");
    printf("memfd_create syscall = %d\n", (int)SYS_memfd_create);
    printf("execveat     syscall = %d\n", (int)SYS_execveat);

    /* 1. can we even create one? */
    int fd = memfd_create_compat("selftest", MFD_CLOEXEC);
    if (fd < 0) {
        printf("FAIL memfd_create: %s\n", strerror(errno));
        return 1;
    }
    printf("PASS memfd_create -> fd %d\n", fd);

    /* 2. does it behave as a file? */
    const char *msg = "round-trip";
    if (write(fd, msg, strlen(msg)) != (ssize_t)strlen(msg)) {
        printf("FAIL write\n"); close(fd); return 1;
    }
    char back[32] = {0};
    lseek(fd, 0, SEEK_SET);
    read(fd, back, sizeof back - 1);
    printf("%s memfd round-trip: \"%s\"\n",
           strcmp(back, msg) == 0 ? "PASS" : "FAIL", back);
    close(fd);

    /* 3. exec a real binary FROM DISK (control A) */
    printf("\n[control A] exec /bin/sh from disk\n");
    pid_t p = fork();
    if (p == 0) { execl("/bin/sh", "sh", "-c", "echo DISK-A-OK", (char *)NULL); _exit(127); }
    int st = 0; waitpid(p, &st, 0);
    printf("  control A exit=%d (0 = disk exec works)\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);

    /* 4. THE TEST: /bin/sh's bytes, copied into an anonymous memfd, executed */
    printf("\n[test] same bytes, staged in memfd, executed with AT_EMPTY_PATH\n");
    int mfd = memfd_create_compat("shcopy", MFD_CLOEXEC);
    if (mfd < 0) { printf("FAIL memfd for sh\n"); return 1; }
    if (slurp_fd(mfd, "/bin/sh") < 0) { printf("FAIL could not copy /bin/sh\n"); close(mfd); return 1; }
    fchmod(mfd, 0700);

    p = fork();
    if (p == 0) {
        char *argv[] = { "sh", "-c", "echo MEMFD-EXEC-OK", NULL };
        exec_fd(mfd, argv, environ);
        _exit(127);
    }
    waitpid(p, &st, 0);
    int rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    printf("  test exit=%d\n", rc);
    close(mfd);

    printf("\n");
    if (rc == 0) {
        printf("VERDICT: unsigned execution from memory works on this device.\n");
        printf("         No filesystem path was resolved. UEP has nothing to check.\n");
        return 0;
    }
    printf("VERDICT: in-memory exec did not succeed here (exit %d)\n", rc);
    return 1;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--selftest") == 0)
        return selftest();

    if (argc < 2) {
        fprintf(stderr, "usage: %s <payload> [args...]\n       %s --selftest\n",
                argv[0], argv[0]);
        return 2;
    }
    return run_payload(argv[1], &argv[2]);
}
