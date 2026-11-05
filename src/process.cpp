#include "process.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sodium.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

extern char** environ;

namespace ang {

namespace {

std::vector<char*> make_argv(const std::vector<std::string>& args) {
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& a : args) {
        argv.push_back(const_cast<char*>(a.c_str()));
    }
    argv.push_back(nullptr);
    return argv;
}

// 本体では SIGPIPE を無視しているので、子プロセスでは既定に戻す
void reset_sigpipe(posix_spawnattr_t& attr) {
    sigset_t defaults;
    sigemptyset(&defaults);
    sigaddset(&defaults, SIGPIPE);
    posix_spawnattr_setsigdefault(&attr, &defaults);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF);
}

int wait_pid(pid_t pid) {
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return -1;
}

// ファイル記述子を閉じ忘れないための小さなラッパー
class Fd {
public:
    Fd() = default;
    explicit Fd(int fd) : fd_(fd) {}
    ~Fd() { reset(); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }
    int get() const { return fd_; }
    bool open() const { return fd_ >= 0; }
    void reset() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_ = -1;
};

// 0〜3 番と重ならない番号に移し、close-on-exec を付ける（子では dup2 した先だけが残る）
Fd high_fd(int fd) {
    const int moved = ::fcntl(fd, F_DUPFD_CLOEXEC, 10);
    const int err = errno;
    ::close(fd);
    if (moved < 0) {
        throw std::runtime_error(std::string("fcntl に失敗しました: ") + std::strerror(err));
    }
    return Fd(moved);
}

struct PipePair {
    Fd read;
    Fd write;
};

PipePair make_pipe() {
    int fds[2];
    if (::pipe(fds) != 0) {
        throw std::runtime_error(std::string("pipe の作成に失敗しました: ") + std::strerror(errno));
    }
    PipePair p;
    p.read = high_fd(fds[0]);
    p.write = high_fd(fds[1]);
    return p;
}

void set_nonblocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        throw std::runtime_error(std::string("fcntl に失敗しました: ") + std::strerror(errno));
    }
}

}  // namespace

ChildProcess ChildProcess::spawn(const std::vector<std::string>& args, Pipe pipe) {
    int fds[2];
    if (::pipe(fds) != 0) {
        throw std::runtime_error(std::string("pipe の作成に失敗しました: ") + std::strerror(errno));
    }
    const bool from_child = pipe == Pipe::FromChild;
    const int child_end = from_child ? fds[1] : fds[0];
    const int parent_end = from_child ? fds[0] : fds[1];

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, child_end, from_child ? STDOUT_FILENO : STDIN_FILENO);
    posix_spawn_file_actions_addclose(&actions, child_end);
    posix_spawn_file_actions_addclose(&actions, parent_end);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    reset_sigpipe(attr);

    std::vector<char*> argv = make_argv(args);
    pid_t pid = -1;
    const int rc = posix_spawnp(&pid, argv[0], &actions, &attr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    ::close(child_end);

    if (rc != 0) {
        ::close(parent_end);
        throw std::runtime_error("コマンドを起動できません: " + args[0] + ": " + std::strerror(rc));
    }

    std::FILE* stream = ::fdopen(parent_end, from_child ? "rb" : "wb");
    if (stream == nullptr) {
        ::close(parent_end);
        wait_pid(pid);
        throw std::runtime_error(std::string("fdopen に失敗しました: ") + std::strerror(errno));
    }
    return ChildProcess(pid, stream);
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept : pid_(other.pid_), stream_(other.stream_) {
    other.pid_ = -1;
    other.stream_ = nullptr;
}

ChildProcess::~ChildProcess() {
    if (pid_ > 0) {
        wait();
    }
}

int ChildProcess::wait() {
    if (stream_ != nullptr) {
        std::fclose(stream_);
        stream_ = nullptr;
    }
    if (pid_ <= 0) {
        return -1;
    }
    const int code = wait_pid(pid_);
    pid_ = -1;
    return code;
}

std::string run_capture(const std::vector<std::string>& argv, int& exit_code) {
    ChildProcess child = ChildProcess::spawn(argv, ChildProcess::Pipe::FromChild);
    std::string output;
    char buf[4096];
    std::size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), child.stream())) > 0) {
        output.append(buf, n);
    }
    exit_code = child.wait();
    return output;
}

PipedResult run_piped(const std::vector<std::string>& args, const std::string& input,
                      const std::string* fd3_input) {
    PipePair in = make_pipe();
    PipePair out = make_pipe();
    PipePair err = make_pipe();
    PipePair extra;
    if (fd3_input != nullptr) {
        extra = make_pipe();
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, in.read.get(), STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, out.write.get(), STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, err.write.get(), STDERR_FILENO);
    if (fd3_input != nullptr) {
        posix_spawn_file_actions_adddup2(&actions, extra.read.get(), 3);
    }

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    reset_sigpipe(attr);

    std::vector<char*> argv = make_argv(args);
    pid_t pid = -1;
    const int rc = posix_spawn(&pid, argv[0], &actions, &attr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        throw std::runtime_error("コマンドを起動できません: " + args[0] + ": " + std::strerror(rc));
    }
    // 子に渡した側は親では閉じる
    in.read.reset();
    out.write.reset();
    err.write.reset();
    extra.read.reset();

    struct Writer {
        Fd* fd;
        const std::string* data;
        std::size_t offset;
    };
    struct Reader {
        Fd* fd;
        std::string* data;
    };
    PipedResult result;
    result.out.reserve(16 * 1024);  // 復号した鍵が入るので、なるべく再確保させない
    std::vector<Writer> writers{{&in.write, &input, 0}};
    if (fd3_input != nullptr) {
        writers.push_back({&extra.write, fd3_input, 0});
    }
    std::vector<Reader> readers{{&out.read, &result.out}, {&err.read, &result.err}};
    for (auto& w : writers) {
        set_nonblocking(w.fd->get());
        if (w.data->empty()) {
            w.fd->reset();
        }
    }

    char buf[4096];
    while (true) {
        std::vector<pollfd> fds;
        for (const auto& w : writers) {
            if (w.fd->open()) fds.push_back({w.fd->get(), POLLOUT, 0});
        }
        for (const auto& r : readers) {
            if (r.fd->open()) fds.push_back({r.fd->get(), POLLIN, 0});
        }
        if (fds.empty()) {
            break;
        }
        if (::poll(fds.data(), static_cast<nfds_t>(fds.size()), -1) < 0) {
            if (errno == EINTR) continue;
            const int e = errno;
            ::kill(pid, SIGTERM);
            wait_pid(pid);
            throw std::runtime_error(std::string("poll に失敗しました: ") + std::strerror(e));
        }
        for (const auto& p : fds) {
            if (p.revents == 0) continue;
            for (auto& w : writers) {
                if (w.fd->get() != p.fd) continue;
                const ssize_t n = ::write(p.fd, w.data->data() + w.offset, w.data->size() - w.offset);
                if (n > 0) {
                    w.offset += static_cast<std::size_t>(n);
                }
                // 書き終えたら閉じて EOF を伝える。子が先に閉じた (EPIPE) 場合も閉じる
                if (w.offset >= w.data->size() || (n < 0 && errno != EAGAIN && errno != EINTR)) {
                    w.fd->reset();
                }
            }
            for (auto& r : readers) {
                if (r.fd->get() != p.fd) continue;
                const ssize_t n = ::read(p.fd, buf, sizeof(buf));
                if (n > 0) {
                    r.data->append(buf, static_cast<std::size_t>(n));
                } else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
                    r.fd->reset();
                }
            }
        }
    }
    sodium_memzero(buf, sizeof(buf));
    result.exit_code = wait_pid(pid);
    return result;
}

int run_command(const std::vector<std::string>& args) {
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    reset_sigpipe(attr);
    std::vector<char*> argv = make_argv(args);
    pid_t pid = -1;
    const int rc = posix_spawnp(&pid, argv[0], nullptr, &attr, argv.data(), environ);
    posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        throw std::runtime_error("コマンドを起動できません: " + args[0] + ": " + std::strerror(rc));
    }
    return wait_pid(pid);
}

}  // namespace ang
