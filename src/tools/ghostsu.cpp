/*
 * ghostsu — temporary root for adb, no kernel module.
 *
 * One binary, two roles:
 *
 *   ghostsu --agent          started by the rooted handoff script. It already
 *                            runs with uid 0 (init_cred) and SELinux permissive,
 *                            so it simply stays alive and serves requests.
 *   ghostsu -c "id"          client: asks the agent to run a command as root,
 *                            streams its stdout/stderr back, exits with its code.
 *   ghostsu                  client: hands the terminal to a root shell.
 *   ghostsu --ping           exit 0 when the agent is reachable.
 *
 * The agent listens on the abstract unix socket "ghostsu.v1" — no filesystem
 * node, no permissions to collide with, and nothing that survives a reboot.
 *
 * Why this instead of a setuid binary or KernelSU: /data is mounted nosuid, so
 * a setuid helper cannot elevate, and ksud late-load needs a KernelSU driver
 * that a stock kernel does not have. The exploit's rooted child already holds
 * init_cred; this keeps that authority reachable from any adb shell until the
 * next reboot.
 *
 * This is a deliberate, temporary research root: while the agent runs, any
 * process on the device that can reach the socket can use it. Do not leave it
 * running outside a controlled test.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#ifndef GHOSTSU_SHELL
#define GHOSTSU_SHELL "/system/bin/sh"
#endif

namespace {
    constexpr char kSocketName[] = "ghostsu.v1";
    constexpr uint32_t kMagic = 0x47535531U; /* "GSU1" */
    constexpr uint32_t kKindExec = 0;
    constexpr uint32_t kKindShell = 1;
    constexpr uint32_t kEndOfStream = 0xffffffffU;
    constexpr size_t kMaxCommand = 8192;

    struct Header {
        uint32_t magic;
        uint32_t kind;
        uint32_t length;
    };

    struct WinSize {
        uint16_t rows;
        uint16_t cols;
        uint16_t xpixel;
        uint16_t ypixel;
    };

    socklen_t socket_address(sockaddr_un &addr) {
        std::memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path + 1, kSocketName, sizeof(kSocketName) - 1);
        return static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 +
                                      (sizeof(kSocketName) - 1));
    }

    bool write_full(int32_t fd, const void *buffer, size_t length) {
        const char *cursor = static_cast<const char *>(buffer);
        while (length > 0) {
            const ssize_t written = write(fd, cursor, length);
            if (written < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (written == 0) return false;
            cursor += written;
            length -= static_cast<size_t>(written);
        }
        return true;
    }

    bool read_full(int32_t fd, void *buffer, size_t length) {
        char *cursor = static_cast<char *>(buffer);
        while (length > 0) {
            const ssize_t got = read(fd, cursor, length);
            if (got < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (got == 0) return false;
            cursor += got;
            length -= static_cast<size_t>(got);
        }
        return true;
    }

    /* Best effort: the exploit leaves SELinux permissive, but a policy reload or
     * a second actor can re-enable it, and an enforcing kernel domain would make
     * the per-request /system/bin/sh exec fail. */
    void keep_permissive() {
        const int32_t fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
        if (fd < 0) return;
        const char zero[] = "0";
        (void) write(fd, zero, sizeof(zero) - 1);
        close(fd);
    }

    void log_line(const char *text) {
        const int32_t fd = open("/data/local/tmp/.ghostsu.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) return;
        (void) write(fd, text, std::strlen(text));
        close(fd);
    }

    /* ---------------------------------------------------------------- agent */

    void serve_exec(int32_t client, const std::string &command) {
        int32_t pipe_fds[2] = {-1, -1};
        if (pipe2(pipe_fds, O_CLOEXEC) < 0) return;

        const pid_t child = fork();
        if (child == 0) {
            close(pipe_fds[0]);
            (void) dup2(pipe_fds[1], STDOUT_FILENO);
            (void) dup2(pipe_fds[1], STDERR_FILENO);
            close(pipe_fds[1]);
            execl(GHOSTSU_SHELL, "sh", "-c", command.c_str(), static_cast<char *>(nullptr));
            _exit(127);
        }
        close(pipe_fds[1]);
        if (child < 0) {
            close(pipe_fds[0]);
            return;
        }

        char buffer[4096];
        for (;;) {
            const ssize_t got = read(pipe_fds[0], buffer, sizeof(buffer));
            if (got > 0) {
                const uint32_t length = static_cast<uint32_t>(got);
                if (!write_full(client, &length, sizeof(length)) ||
                    !write_full(client, buffer, static_cast<size_t>(got))) {
                    break;
                }
                continue;
            }
            if (got < 0 && errno == EINTR) continue;
            break;
        }
        close(pipe_fds[0]);

        int32_t status = 0;
        if (waitpid(child, &status, 0) == child) {
            /* reaped */
        }
        uint32_t code = 127;
        if (WIFEXITED(status)) code = static_cast<uint32_t>(WEXITSTATUS(status));
        else if (WIFSIGNALED(status)) code = static_cast<uint32_t>(128 + WTERMSIG(status));

        const uint32_t end = kEndOfStream;
        (void) write_full(client, &end, sizeof(end));
        (void) write_full(client, &code, sizeof(code));
    }

    void serve_shell(int32_t client, const WinSize &size) {
        struct winsize native_size {};
        native_size.ws_row = size.rows;
        native_size.ws_col = size.cols;
        native_size.ws_xpixel = size.xpixel;
        native_size.ws_ypixel = size.ypixel;
        if (native_size.ws_row == 0) native_size.ws_row = 40;
        if (native_size.ws_col == 0) native_size.ws_col = 120;

        int32_t master = -1;
        const pid_t child = forkpty(&master, nullptr, nullptr, &native_size);
        if (child == 0) {
            execl(GHOSTSU_SHELL, "sh", "-i", static_cast<char *>(nullptr));
            _exit(127);
        }
        if (child < 0) return;

        bool client_open = true;
        for (;;) {
            struct pollfd fds[2] = {{master, POLLIN, 0},
                                    {client_open ? client : -1, POLLIN, 0}};
            const int32_t ready = poll(fds, 2, -1);
            if (ready < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if ((fds[0].revents & (POLLIN | POLLHUP)) != 0) {
                char buffer[4096];
                const ssize_t got = read(master, buffer, sizeof(buffer));
                if (got <= 0) {
                    if (got < 0 && errno == EINTR) continue;
                    break;
                }
                if (!write_full(client, buffer, static_cast<size_t>(got))) break;
            }
            if (client_open && (fds[1].revents & (POLLIN | POLLHUP)) != 0) {
                char buffer[4096];
                const ssize_t got = read(client, buffer, sizeof(buffer));
                if (got <= 0) {
                    if (got < 0 && errno == EINTR) continue;
                    /* A pty master cannot be half-closed; send EOT so a canonical
                     * line discipline delivers EOF, then drain the remaining
                     * output until the shell exits. */
                    const char eot = 4;
                    (void) write(master, &eot, 1);
                    client_open = false;
                    continue;
                }
                if (!write_full(master, buffer, static_cast<size_t>(got))) break;
            }
        }
        close(master);
        int32_t status = 0;
        if (waitpid(child, &status, WNOHANG) == 0) {
            (void) kill(child, SIGHUP);
            (void) waitpid(child, &status, 0);
        }
    }

    void serve_client(int32_t client) {
        Header header{};
        if (!read_full(client, &header, sizeof(header))) return;
        if (header.magic != kMagic || header.kind > kKindShell) return;
        if (header.length > kMaxCommand) return;

        if (header.kind == kKindShell) {
            WinSize size{};
            (void) read_full(client, &size, sizeof(size));
            keep_permissive();
            serve_shell(client, size);
            return;
        }

        std::string command(header.length, '\0');
        if (!command.empty() && !read_full(client, command.data(), command.size())) return;
        keep_permissive();
        serve_exec(client, command);
    }

    int32_t agent_run() {
        signal(SIGHUP, SIG_IGN);
        signal(SIGPIPE, SIG_IGN);
        /* Auto-reap connection workers. The worker resets this to SIG_DFL so it
         * can still collect the exit status of the command it runs. */
        signal(SIGCHLD, SIG_IGN);
        (void) setsid();
        (void) chdir("/");
        (void) umask(077);
        (void) prctl(PR_SET_NAME, "ghostsu_agent");

        const int32_t oom = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
        if (oom >= 0) {
            const char value[] = "-1000";
            (void) write(oom, value, sizeof(value) - 1);
            close(oom);
        }

        const int32_t listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (listener < 0) return 1;
        sockaddr_un address{};
        const socklen_t address_length = socket_address(address);
        if (bind(listener, reinterpret_cast<const sockaddr *>(&address), address_length) < 0) {
            close(listener);
            return 1;
        }
        if (listen(listener, 16) < 0) {
            close(listener);
            return 1;
        }

        {
            char line[160];
            std::string context;
            const int32_t ctx = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
            if (ctx >= 0) {
                char buffer[128] = {};
                const ssize_t got = read(ctx, buffer, sizeof(buffer) - 1);
                if (got > 0) context.assign(buffer, static_cast<size_t>(got));
                close(ctx);
            }
            snprintf(line, sizeof(line), "[*] agent start uid=%u label=%s\n",
                     static_cast<unsigned>(getuid()), context.c_str());
            log_line(line);
        }
        keep_permissive();

        for (;;) {
            while (waitpid(-1, nullptr, WNOHANG) > 0) {
            }
            const int32_t client = accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
            if (client < 0) {
                if (errno == EINTR) continue;
                continue;
            }
            const pid_t worker = fork();
            if (worker == 0) {
                close(listener);
                signal(SIGHUP, SIG_DFL);
                signal(SIGCHLD, SIG_DFL);
                serve_client(client);
                close(client);
                _exit(0);
            }
            close(client);
            if (worker < 0) continue;
        }
    }

    /* --------------------------------------------------------------- client */

    int32_t agent_connect() {
        const int32_t fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return -1;
        sockaddr_un address{};
        const socklen_t address_length = socket_address(address);
        if (connect(fd, reinterpret_cast<const sockaddr *>(&address), address_length) < 0) {
            close(fd);
            return -1;
        }
        return fd;
    }

    int32_t client_exec(const std::string &command) {
        const int32_t fd = agent_connect();
        if (fd < 0) {
            fprintf(stderr, "ghostsu: agent not running (temporary root is not active)\n");
            return 127;
        }
        const Header header{kMagic, kKindExec, static_cast<uint32_t>(command.size())};
        if (!write_full(fd, &header, sizeof(header)) ||
            (!command.empty() && !write_full(fd, command.data(), command.size()))) {
            close(fd);
            return 127;
        }

        int32_t result = 127;
        char buffer[4096];
        for (;;) {
            uint32_t length = 0;
            if (!read_full(fd, &length, sizeof(length))) break;
            if (length == kEndOfStream) {
                uint32_t code = 127;
                if (read_full(fd, &code, sizeof(code))) result = static_cast<int32_t>(code);
                break;
            }
            uint32_t remaining = length;
            while (remaining > 0) {
                const size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
                if (!read_full(fd, buffer, chunk)) break;
                (void) write(STDOUT_FILENO, buffer, chunk);
                remaining -= static_cast<uint32_t>(chunk);
            }
        }
        close(fd);
        return result;
    }

    struct termios g_saved_termios {};
    bool g_termios_saved = false;

    void restore_terminal() {
        if (g_termios_saved) (void) tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
    }

    WinSize terminal_size() {
        struct winsize native_size {};
        WinSize size{40, 120, 0, 0};
        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &native_size) == 0) {
            size.rows = native_size.ws_row;
            size.cols = native_size.ws_col;
            size.xpixel = native_size.ws_xpixel;
            size.ypixel = native_size.ws_ypixel;
        }
        return size;
    }

    int32_t client_shell() {
        const int32_t fd = agent_connect();
        if (fd < 0) {
            fprintf(stderr, "ghostsu: agent not running (temporary root is not active)\n");
            return 127;
        }
        const Header header{kMagic, kKindShell, 0};
        const WinSize size = terminal_size();
        if (!write_full(fd, &header, sizeof(header)) || !write_full(fd, &size, sizeof(size))) {
            close(fd);
            return 127;
        }

        if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &g_saved_termios) == 0) {
            struct termios raw = g_saved_termios;
            cfmakeraw(&raw);
            if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) {
                g_termios_saved = true;
                (void) atexit(restore_terminal);
            }
        }

        int32_t result = 0;
        bool stdin_open = true;
        for (;;) {
            struct pollfd fds[2] = {{fd, POLLIN, 0},
                                    {stdin_open ? STDIN_FILENO : -1, POLLIN, 0}};
            const int32_t ready = poll(fds, 2, -1);
            if (ready < 0) {
                if (errno == EINTR) continue;
                result = 1;
                break;
            }
            if ((fds[0].revents & (POLLIN | POLLHUP)) != 0) {
                char buffer[4096];
                const ssize_t got = read(fd, buffer, sizeof(buffer));
                if (got <= 0) {
                    if (got < 0 && errno == EINTR) continue;
                    break;
                }
                (void) write(STDOUT_FILENO, buffer, static_cast<size_t>(got));
            }
            if (stdin_open && (fds[1].revents & (POLLIN | POLLHUP)) != 0) {
                char buffer[4096];
                const ssize_t got = read(STDIN_FILENO, buffer, sizeof(buffer));
                if (got <= 0) {
                    if (got < 0 && errno == EINTR) continue;
                    /* Half-close and keep draining: the shell still has output
                     * (and a final exit) to deliver after a piped stdin ends. */
                    (void) shutdown(fd, SHUT_WR);
                    stdin_open = false;
                    continue;
                }
                if (!write_full(fd, buffer, static_cast<size_t>(got))) break;
            }
        }
        restore_terminal();
        close(fd);
        return result;
    }

    std::string join_arguments(int32_t argc, char **argv, int32_t first) {
        std::string command;
        for (int32_t i = first; i < argc; i++) {
            if (!command.empty()) command.push_back(' ');
            command.append(argv[i]);
        }
        return command;
    }
} // namespace

int main(int argc, char **argv) {
    if (argc >= 2 && std::strcmp(argv[1], "--agent") == 0) return agent_run();
    if (argc >= 2 && std::strcmp(argv[1], "--ping") == 0) {
        const int32_t fd = agent_connect();
        if (fd < 0) return 1;
        close(fd);
        return 0;
    }
    if (argc >= 3 && std::strcmp(argv[1], "-c") == 0) return client_exec(argv[2]);
    if (argc >= 2) return client_exec(join_arguments(argc, argv, 1));
    return client_shell();
}
