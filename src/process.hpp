// 子プロセス（tar, osascript, open, gpg）の起動
#pragma once

#include <sys/types.h>

#include <cstdio>
#include <string>
#include <vector>

namespace ang {

class ChildProcess {
public:
    enum class Pipe {
        FromChild,  // 子の標準出力を読む
        ToChild,    // 子の標準入力へ書く
    };

    static ChildProcess spawn(const std::vector<std::string>& argv, Pipe pipe);

    ChildProcess(ChildProcess&& other) noexcept;
    ChildProcess& operator=(ChildProcess&&) = delete;
    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;
    ~ChildProcess();

    std::FILE* stream() { return stream_; }

    // パイプを閉じて終了を待ち、終了コードを返す（シグナル終了は 128 + シグナル番号）
    int wait();

private:
    ChildProcess(pid_t pid, std::FILE* stream) : pid_(pid), stream_(stream) {}

    pid_t pid_ = -1;
    std::FILE* stream_ = nullptr;
};

// コマンドを実行して標準出力を返す
std::string run_capture(const std::vector<std::string>& argv, int& exit_code);

struct PipedResult {
    int exit_code = -1;
    std::string out;  // 標準出力
    std::string err;  // 標準エラー
};

// 標準入力に input、（fd3_input があれば）ファイル記述子 3 に *fd3_input を書き込み、
// 標準出力と標準エラーを受け取る（gpg 用。小さなデータを想定）
PipedResult run_piped(const std::vector<std::string>& argv, const std::string& input,
                      const std::string* fd3_input = nullptr);

// コマンドを実行して終了コードを返す（標準入出力は引き継ぐ）
int run_command(const std::vector<std::string>& argv);

}  // namespace ang
