#include "prompt.hpp"

#include "process.hpp"

#include <termios.h>
#include <unistd.h>

#include <iostream>
#include <vector>

namespace ang {

namespace {

std::optional<std::string> read_tty_line(const std::string& message) {
    std::cerr << message << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) {
        std::cerr << '\n';
        return std::nullopt;
    }
    return line;
}

// AppleScript を実行する。メッセージは argv で渡すのでエスケープは不要
std::optional<std::string> run_osascript(const std::string& body, const std::string& message) {
#ifdef __APPLE__
    int code = 0;
    std::string out = run_capture({"osascript", "-e", "on run argv", "-e", body, "-e", "end run", message}, code);
    if (code != 0) {
        return std::nullopt;  // キャンセルボタン
    }
    if (!out.empty() && out.back() == '\n') {
        out.pop_back();
    }
    return out;
#else
    (void)body;
    (void)message;
    throw std::runtime_error("端末がないため入力を受け付けられません");
#endif
}

}  // namespace

bool gui_mode() {
    static const bool gui = ::isatty(STDIN_FILENO) == 0;
    return gui;
}

std::optional<std::string> ask_line(const std::string& message) {
    if (gui_mode()) {
        return run_osascript(
            "text returned of (display dialog (item 1 of argv) default answer \"\" with title \"Ango\")", message);
    }
    return read_tty_line(message);
}

std::optional<std::string> ask_passphrase(const std::string& message) {
    if (gui_mode()) {
        return run_osascript(
            "text returned of (display dialog (item 1 of argv) default answer \"\" with hidden answer "
            "with title \"Ango\")",
            message);
    }

    termios old_attr{};
    const bool has_attr = ::tcgetattr(STDIN_FILENO, &old_attr) == 0;
    if (has_attr) {
        termios no_echo = old_attr;
        no_echo.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(STDIN_FILENO, TCSANOW, &no_echo);
    }
    std::optional<std::string> line = read_tty_line(message);
    if (has_attr) {
        ::tcsetattr(STDIN_FILENO, TCSANOW, &old_attr);
        std::cerr << '\n';
    }
    return line;
}

std::optional<std::string> ask_file_location(const std::string& message) {
    if (gui_mode()) {
        return run_osascript("POSIX path of (choose file with prompt (item 1 of argv))", message);
    }
    return read_tty_line(message);
}

void show_error(const std::string& message) {
    if (!gui_mode()) {
        return;
    }
    try {
        run_osascript("display alert \"Ango\" message (item 1 of argv) as critical", message);
    } catch (const std::exception&) {
        // ダイアログが出せなくても本来のエラーは標準エラーに出ている
    }
}

}  // namespace ang
