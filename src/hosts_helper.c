#include <stdio.h>
#include <unistd.h>

/* Root LaunchDaemon entry point. The backend is installed root-owned beside
 * this binary. Isolated Python ignores PYTHONPATH, the user site and the
 * caller's working directory. Never execute user-writable Python as root. */
#define BACKEND "/Library/Application Support/ClaudeGuard/pf_controller.py"

int main(int argc, char **argv) {
    if (argc != 2 || geteuid() != 0) {
        fprintf(stderr, "usage (as root): hosts-helper <config-dir> | --unblock\n");
        return 2;
    }
    char *args[] = {"/usr/bin/python3", "-I", BACKEND, argv[1], NULL};
    execv(args[0], args);
    perror("hosts-helper: cannot start network backend");
    return 1;
}
