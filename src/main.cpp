// ango: 指定ファイル/フォルダを公開鍵方式で暗号化・復号するコマンド
#include "crypto.hpp"
#include "gpg.hpp"
#include "keystore.hpp"
#include "process.hpp"
#include "prompt.hpp"
#include "session.hpp"

#include <fcntl.h>
#include <sys/mount.h>
#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#ifndef ANG_VERSION
#define ANG_VERSION "dev"
#endif

namespace ang {
namespace {

constexpr const char* kAngExt = ".ang";
constexpr int kPassphraseAttempts = 3;

struct Options {
    bool keep = false;        // 元のファイルを残す
    bool force = false;       // 出力先が既にあれば上書きする
    bool open_after = false;  // 復号後に開く
    bool allow_unsigned = false;  // 署名のない旧形式も復号する
    std::vector<std::string> paths;
};

// 鍵が使えないため処理全体を中止する（USB 未挿入など）
class KeyUnavailable : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct FileCloser {
    void operator()(std::FILE* f) const {
        if (f != nullptr) std::fclose(f);
    }
};
using FilePtr = std::unique_ptr<std::FILE, FileCloser>;

bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string random_suffix() {
    unsigned char bytes[6];
    randombytes_buf(bytes, sizeof(bytes));
    char hex[sizeof(bytes) * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), bytes, sizeof(bytes));
    return hex;
}

// 同じフォルダに一時ファイルを作り、成功したら目的の名前に置き換える
class TempOutput {
public:
    explicit TempOutput(const fs::path& target)
        : path_(target.parent_path() / ("." + target.filename().string() + ".tmp-" + random_suffix())) {
        const int fd = ::open(path_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) {
            throw std::runtime_error("ファイルを作成できません: " + path_.string() + ": " + std::strerror(errno));
        }
        file_.reset(::fdopen(fd, "wb"));
        if (!file_) {
            ::close(fd);
            ::unlink(path_.c_str());
            throw std::runtime_error(std::string("fdopen に失敗しました: ") + std::strerror(errno));
        }
    }

    ~TempOutput() {
        if (!committed_) {
            file_.reset();
            std::error_code ec;
            fs::remove(path_, ec);
        }
    }

    std::FILE* get() { return file_.get(); }

    void commit(const fs::path& target) {
        std::FILE* f = file_.release();
        const bool ok = std::fflush(f) == 0 && ::fsync(::fileno(f)) == 0;
        const int err = errno;
        if (std::fclose(f) != 0 || !ok) {
            throw std::runtime_error("書き込みに失敗しました: " + path_.string() + ": " + std::strerror(err));
        }
        fs::rename(path_, target);
        committed_ = true;
    }

private:
    fs::path path_;
    FilePtr file_;
    bool committed_ = false;
};

// 一時フォルダ（tar 展開用）。commit しなければ中身ごと削除する
class TempDir {
public:
    explicit TempDir(const fs::path& parent) {
        std::string tmpl = (parent / ".ang-extract-XXXXXX").string();
        if (::mkdtemp(tmpl.data()) == nullptr) {
            throw std::runtime_error("一時フォルダを作成できません: " + parent.string() + ": " + std::strerror(errno));
        }
        path_ = tmpl;
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

FilePtr open_for_read(const fs::path& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        throw std::runtime_error("ファイルを開けません: " + path.string() + ": " + std::strerror(errno));
    }
    std::FILE* f = ::fdopen(fd, "rb");
    if (f == nullptr) {
        ::close(fd);
        throw std::runtime_error(std::string("fdopen に失敗しました: ") + std::strerror(errno));
    }
    return FilePtr(f);
}

// 末尾の "/" を除いた絶対パス
fs::path absolute_target(const std::string& arg) {
    fs::path p = fs::absolute(normalize_user_path(arg)).lexically_normal();
    if (p.filename().empty()) {
        p = p.parent_path();
    }
    return p;
}

std::string display(const fs::path& p) { return p.string(); }

// フォルダが指定されたときは、その中の鍵ファイル（ango の鍵 → GPG の鍵の設定の順）を使う
fs::path key_file_in(const fs::path& dir) {
    const fs::path gpg = dir / kGpgKeyFileName;
    if (!fs::exists(dir / kSecretKeyFileName) && fs::is_regular_file(gpg)) {
        return gpg;
    }
    return dir / kSecretKeyFileName;
}

const std::string kKeyFilesText =
    std::string("秘密鍵ファイル (") + kSecretKeyFileName + ") または GPG の鍵の設定ファイル (" + kGpgKeyFileName + ")";

// ---------------------------------------------------------------- 鍵の取得

// 秘密鍵ファイルの場所を決める。
// 保存済みの場所に無いとき、ask_if_missing なら場所を尋ね、そうでなければ USB の挿入を促して中止する。
// 場所がまだ保存されていなければ（初回）常に尋ねる。
fs::path locate_secret_key(bool ask_if_missing) {
    const std::optional<fs::path> saved = load_secret_key_location();
    if (saved && fs::is_regular_file(*saved)) {
        return *saved;
    }
    if (saved && !ask_if_missing) {
        throw KeyUnavailable("秘密鍵が見つかりません。USB を差してから、もう一度実行してください。\n  " +
                             display(*saved));
    }

    std::string message;
    if (saved) {
        message = "保存されている場所に秘密鍵が見つかりません:\n  " + display(*saved) +
                  "\nUSB を挿入して、" + kKeyFilesText + " の場所を指定してください。";
    } else {
        message = kKeyFilesText + " の場所を指定してください。";
    }

    while (true) {
        std::optional<std::string> answer;
        if (gui_mode()) {
            answer = ask_file_location(message);
        } else {
            const std::string hint = saved ? "\n（USB を挿入して Enter で同じ場所を再確認）" : "";
            answer = ask_file_location(message + hint + "\n> ");
        }
        if (!answer) {
            throw Cancelled();
        }

        fs::path candidate = normalize_user_path(*answer);
        if (candidate.empty()) {
            if (!saved) {
                throw Cancelled();
            }
            candidate = *saved;
        }
        if (fs::is_directory(candidate)) {
            candidate = key_file_in(candidate);
        }
        if (fs::is_regular_file(candidate)) {
            candidate = fs::absolute(candidate).lexically_normal();
            save_secret_key_location(candidate);
            return candidate;
        }
        message = "秘密鍵ファイルが見つかりません:\n  " + display(candidate) + "\nもう一度指定してください。";
    }
}

// 鍵を（1 回の実行につき 1 度だけ）用意する。
// ang_secret.key なら ango の鍵（パスフレーズは最初に必要になったときに尋ねる）、ang_gpg.key なら GPG の鍵
class SecretKeyProvider {
public:
    explicit SecretKeyProvider(bool ask_if_missing) : ask_if_missing_(ask_if_missing) {}

    KeyOps& get() {
        if (ops_) {
            return *ops_;
        }
        path_ = locate_secret_key(ask_if_missing_);
        if (is_gpg_key_file(path_)) {
            ops_ = std::make_unique<GpgKeyOps>(read_gpg_key_file(path_));
        } else {
            ops_ = std::make_unique<SodiumKeyOps>([this]() -> const KeyPair& { return load_keypair(); });
        }
        return *ops_;
    }

private:
    const KeyPair& load_keypair() {
        if (keys_) {
            return *keys_;
        }
        if (std::optional<KeyPair> cached = load_session(path_)) {
            keys_.emplace(std::move(*cached));
            return *keys_;
        }
        for (int attempt = 1;; ++attempt) {
            std::optional<std::string> pass = ask_passphrase("秘密鍵のパスフレーズを入力してください: ");
            if (!pass) {
                throw Cancelled();
            }
            try {
                keys_.emplace(read_secret_key_file(path_, *pass));
                sodium_memzero(pass->data(), pass->size());
                create_session(path_, *keys_);
                return *keys_;
            } catch (const WrongPassphrase&) {
                sodium_memzero(pass->data(), pass->size());
                if (attempt >= kPassphraseAttempts) {
                    throw;
                }
                std::cerr << "パスフレーズが違います。もう一度入力してください。\n";
            }
        }
    }

    bool ask_if_missing_;
    fs::path path_;
    std::unique_ptr<KeyOps> ops_;
    std::optional<KeyPair> keys_;
};

// ---------------------------------------------------------------- 暗号化

void encrypt_path(const std::string& arg, SecretKeyProvider& keys, const Options& opt) {
    const fs::path src = absolute_target(arg);
    const fs::file_status st = fs::symlink_status(src);

    if (!fs::exists(st)) {
        throw std::runtime_error("見つかりません: " + display(src));
    }
    if (fs::is_symlink(st)) {
        // リンクだけ消えて実体が平文のまま残るのを防ぐ
        throw std::runtime_error("シンボリックリンクは暗号化できません（リンク先を指定してください）: " + display(src));
    }
    if (ends_with(src.filename().string(), kAngExt)) {
        throw std::runtime_error("既に暗号化されています: " + display(src));
    }

    const bool is_dir = fs::is_directory(st);
    if (!is_dir && !fs::is_regular_file(st)) {
        throw std::runtime_error("通常のファイルまたはフォルダではありません: " + display(src));
    }

    const fs::path dst = src.parent_path() / (src.filename().string() + (is_dir ? ".tar.ang" : ".ang"));
    if (fs::exists(fs::symlink_status(dst)) && !opt.force) {
        throw std::runtime_error("出力先が既に存在します（上書きは --force）: " + display(dst));
    }

    KeyOps& kp = keys.get();
    TempOutput out(dst);
    if (is_dir) {
        ChildProcess tar = ChildProcess::spawn(
            {"tar", "-cf", "-", "-C", src.parent_path().string(), "./" + src.filename().string()},
            ChildProcess::Pipe::FromChild);
        encrypt_stream(tar.stream(), out.get(), kp, PayloadKind::Tar);
        if (const int code = tar.wait(); code != 0) {
            throw std::runtime_error("tar によるまとめ処理に失敗しました（終了コード " + std::to_string(code) + "）");
        }
    } else {
        FilePtr in = open_for_read(src);
        encrypt_stream(in.get(), out.get(), kp, PayloadKind::File);
    }
    out.commit(dst);

    if (!opt.keep) {
        if (is_dir) {
            fs::remove_all(src);
        } else {
            fs::remove(src);
        }
    }
    std::cout << "暗号化しました: " << display(dst) << '\n';
}

// ---------------------------------------------------------------- 復号

std::vector<fs::path> decrypt_path(const std::string& arg, SecretKeyProvider& keys, const Options& opt) {
    const fs::path src = absolute_target(arg);
    const std::string name = src.filename().string();
    if (!ends_with(name, kAngExt)) {
        throw std::runtime_error("拡張子が .ang ではありません: " + display(src));
    }
    if (!fs::is_regular_file(src)) {
        throw std::runtime_error("見つかりません: " + display(src));
    }

    FilePtr in = open_for_read(src);
    const EncryptedHeader header = read_header(in.get());
    const fs::path parent = src.parent_path();

    std::vector<fs::path> outputs;
    if (header.kind == PayloadKind::File) {
        const fs::path dst = parent / name.substr(0, name.size() - std::strlen(kAngExt));
        if (fs::exists(fs::symlink_status(dst)) && !opt.force) {
            throw std::runtime_error("出力先が既に存在します（上書きは --force）: " + display(dst));
        }
        KeyOps& kp = keys.get();
        verify_header(header, kp, opt.allow_unsigned);
        TempOutput out(dst);
        decrypt_stream(in.get(), out.get(), header, kp);
        out.commit(dst);
        outputs.push_back(dst);
    } else {
        // 一時フォルダに展開し、認証が通ってから元の場所へ移す
        KeyOps& kp = keys.get();
        verify_header(header, kp, opt.allow_unsigned);
        TempDir tmp(parent);
        {
            ChildProcess tar =
                ChildProcess::spawn({"tar", "-xf", "-", "-C", tmp.path().string()}, ChildProcess::Pipe::ToChild);
            decrypt_stream(in.get(), tar.stream(), header, kp);
            if (const int code = tar.wait(); code != 0) {
                throw std::runtime_error("tar による展開に失敗しました（終了コード " + std::to_string(code) + "）");
            }
        }

        std::vector<fs::path> entries;
        for (const auto& entry : fs::directory_iterator(tmp.path())) {
            const fs::path dst = parent / entry.path().filename();
            if (fs::exists(fs::symlink_status(dst)) && !opt.force) {
                throw std::runtime_error("出力先が既に存在します（上書きは --force）: " + display(dst));
            }
            entries.push_back(entry.path());
        }
        for (const auto& entry : entries) {
            const fs::path dst = parent / entry.filename();
            if (opt.force) {
                fs::remove_all(dst);
            }
            fs::rename(entry, dst);
            outputs.push_back(dst);
        }
    }
    in.reset();

    if (!opt.keep) {
        fs::remove(src);
    }
    for (const auto& out : outputs) {
        std::cout << "復号しました: " << display(out) << '\n';
    }
    return outputs;
}

// ---------------------------------------------------------------- コマンド

void print_usage() {
    std::cout << "使い方:\n"
                 "  ango keygen [出力フォルダ]          秘密鍵を作成する（USB を指定してください）\n"
                 "  ango gpg-setup フォルダ [鍵ファイル...] [鍵ID]\n"
                 "                                     USB 上の GPG の鍵を使うように設定する（鍵ファイルは取り込む）\n"
                 "  ango encrypt [オプション] パス...    ファイル/フォルダを暗号化・署名する（.ang / .tar.ang）\n"
                 "  ango decrypt [オプション] パス...    .ang / .tar.ang の署名を確かめて復号する\n"
                 "  ango key-location [パス | --forget]  秘密鍵の場所を表示/設定/消去する\n"
                 "  ango lock                           解錠キャッシュを消し、gpg-agent を止める（次回はパスフレーズが必要）\n"
                 "  ango eject                          ロックしてから、鍵のある USB を取り外す\n"
                 "  ango --version\n"
                 "\n"
                 "オプション:\n"
                 "  -k, --keep    元のファイルを削除しない\n"
                 "  -f, --force   出力先が既にあれば上書きする\n"
                 "  -o, --open    復号後にファイルを開く（decrypt のみ）\n"
                 "  --allow-unsigned  署名のない旧形式のファイルも復号する（decrypt のみ）\n"
                 "\n"
                 "暗号化・復号のどちらにも、USB 上の秘密鍵とパスフレーズが必要です。\n"
                 "一度パスフレーズを入力すると、USB が挿さっている間は最後に使ってから 30 分間入力を省略できます。\n"
                 "GPG の鍵を使う場合、パスフレーズを省略できる時間は gpg-agent の設定に従います。\n";
}

Options parse_options(const std::vector<std::string>& args, bool for_decrypt) {
    Options opt;
    bool only_paths = false;
    for (const auto& a : args) {
        if (!only_paths && a == "--") {
            only_paths = true;
        } else if (!only_paths && (a == "-k" || a == "--keep")) {
            opt.keep = true;
        } else if (!only_paths && (a == "-f" || a == "--force")) {
            opt.force = true;
        } else if (!only_paths && for_decrypt && (a == "-o" || a == "--open")) {
            opt.open_after = true;
        } else if (!only_paths && for_decrypt && a == "--allow-unsigned") {
            opt.allow_unsigned = true;
        } else if (!only_paths && a.size() > 1 && a[0] == '-') {
            throw std::invalid_argument("不明なオプションです: " + a);
        } else {
            opt.paths.push_back(a);
        }
    }
    if (opt.paths.empty()) {
        throw std::invalid_argument("対象のパスを指定してください");
    }
    return opt;
}

// 各パスを処理し、失敗したものはまとめて報告する
template <typename Fn>
int for_each_path(const Options& opt, Fn&& fn) {
    std::vector<std::string> errors;
    for (const auto& path : opt.paths) {
        try {
            fn(path);
        } catch (const Cancelled&) {
            throw;
        } catch (const KeyUnavailable&) {
            throw;
        } catch (const std::exception& e) {
            std::cerr << "エラー: " << e.what() << '\n';
            errors.push_back(e.what());
        }
    }
    if (!errors.empty()) {
        std::string all;
        for (const auto& e : errors) {
            all += e + "\n";
        }
        show_error(all);
        return 1;
    }
    return 0;
}

// path があるボリュームのマウント位置（取得できなければ例外）
std::string mount_point_of(const fs::path& path) {
    struct statfs st {};
    if (::statfs(path.c_str(), &st) != 0) {
        throw std::runtime_error("ディスクの情報を取得できません: " + display(path) + ": " + std::strerror(errno));
    }
    return st.f_mntonname;
}

bool is_startup_volume(const std::string& mount_point) {
    return mount_point == "/" || mount_point == "/System/Volumes/Data";
}

// 鍵を置いた USB のルートに .metadata_never_index を作り、Spotlight に索引を作らせないようにする。
// 索引作成中は USB を取り外せないことがあるため。起動ディスクには作らない。失敗しても警告だけ出す
void disable_spotlight_indexing(const fs::path& key_path) {
#ifdef __APPLE__
    try {
        const std::string mount_point = mount_point_of(key_path);
        if (is_startup_volume(mount_point)) return;
        const fs::path marker = fs::path(mount_point) / ".metadata_never_index";
        if (fs::exists(fs::symlink_status(marker))) return;
        const int fd = ::open(marker.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) {
            throw std::runtime_error(display(marker) + ": " + std::strerror(errno));
        }
        ::close(fd);
        std::cout << "Spotlight がこの USB の索引を作らないように設定しました: " << display(marker) << '\n';
    } catch (const std::exception& e) {
        std::cerr << "警告: Spotlight の索引作成を止める設定ができませんでした: " << e.what() << '\n';
    }
#else
    (void)key_path;
#endif
}

int cmd_keygen(const std::vector<std::string>& args) {
    if (args.size() > 1) {
        throw std::invalid_argument("出力フォルダは 1 つだけ指定してください");
    }
    const fs::path dir = args.empty() ? fs::current_path() : absolute_target(args[0]);
    if (!fs::is_directory(dir)) {
        throw std::runtime_error("フォルダが見つかりません: " + display(dir));
    }
    const fs::path sk_path = dir / kSecretKeyFileName;
    if (fs::exists(fs::symlink_status(sk_path))) {
        throw std::runtime_error("既に鍵ファイルがあります: " + display(sk_path));
    }

    std::optional<std::string> pass = ask_passphrase("新しいパスフレーズを入力してください: ");
    if (!pass) throw Cancelled();
    if (pass->empty()) throw std::runtime_error("パスフレーズを空にはできません");
    std::optional<std::string> confirm = ask_passphrase("確認のため、もう一度入力してください: ");
    if (!confirm) throw Cancelled();
    const bool same = *pass == *confirm;
    sodium_memzero(confirm->data(), confirm->size());
    if (!same) {
        sodium_memzero(pass->data(), pass->size());
        throw std::runtime_error("パスフレーズが一致しません");
    }

    const KeyPair keys = generate_keypair();
    write_secret_key_file(sk_path, keys, *pass);
    sodium_memzero(pass->data(), pass->size());
    save_secret_key_location(sk_path);

    std::cout << "鍵を作成しました: " << display(sk_path) << "\n";
    disable_spotlight_indexing(sk_path);
    std::cout
              << "\n"
              << "暗号化・復号のどちらにもこの秘密鍵が必要です。USB などの取り外し可能なデバイスに置き、\n"
              << "このコンピュータには残さないでください。場所を移した場合は、次回の実行時に場所を尋ねます。\n"
              << "秘密鍵かパスフレーズを失うと復号できなくなるので、バックアップを別の安全な場所に保管してください。\n";
    return 0;
}

int cmd_encrypt(const std::vector<std::string>& args) {
    const Options opt = parse_options(args, false);
    SecretKeyProvider keys(/*ask_if_missing=*/false);
    return for_each_path(opt, [&](const std::string& path) { encrypt_path(path, keys, opt); });
}

int cmd_decrypt(const std::vector<std::string>& args) {
    const Options opt = parse_options(args, true);
    SecretKeyProvider keys(/*ask_if_missing=*/true);
    std::vector<fs::path> opened;
    const int code = for_each_path(opt, [&](const std::string& path) {
        for (auto& out : decrypt_path(path, keys, opt)) {
            opened.push_back(std::move(out));
        }
    });
#ifdef __APPLE__
    if (opt.open_after) {
        for (const auto& p : opened) {
            run_command({"open", p.string()});
        }
    }
#endif
    return code;
}

// 解錠キャッシュ（ango の鍵）と gpg-agent の記憶（GPG の鍵）を消す
void lock_all() {
    const std::optional<fs::path> saved = load_secret_key_location();
    clear_session(saved);
    if (saved && fs::is_regular_file(*saved) && is_gpg_key_file(*saved)) {
        gpg_forget_passphrase(read_gpg_key_file(*saved).homedir);
    }
}

int cmd_key_location(const std::vector<std::string>& args) {
    if (args.empty()) {
        if (const auto saved = load_secret_key_location()) {
            std::cout << display(*saved) << (fs::is_regular_file(*saved) ? "" : "（現在見つかりません）") << '\n';
        } else {
            std::cout << "秘密鍵の場所は保存されていません\n";
        }
        return 0;
    }
    if (args.size() != 1) {
        throw std::invalid_argument("パスは 1 つだけ指定してください");
    }
    if (args[0] == "--forget") {
        lock_all();
        forget_secret_key_location();
        std::cout << "秘密鍵の場所を消去しました\n";
        return 0;
    }
    fs::path p = absolute_target(args[0]);
    if (fs::is_directory(p)) {
        p = key_file_in(p);
    }
    if (!fs::is_regular_file(p)) {
        throw std::runtime_error(kKeyFilesText + " が見つかりません: " + display(p));
    }
    save_secret_key_location(p);
    std::cout << "秘密鍵の場所を保存しました: " << display(p) << '\n';
    return 0;
}

int cmd_gpg_setup(const std::vector<std::string>& args) {
    if (args.empty()) {
        throw std::invalid_argument("gpg-setup には GNUPGHOME にするフォルダを指定してください");
    }
    // 2 つ目以降: 存在するファイルは取り込む鍵ファイル、それ以外は鍵 ID（1 つまで）
    std::vector<fs::path> key_files;
    std::string query;
    for (std::size_t i = 1; i < args.size(); ++i) {
        const fs::path p = absolute_target(args[i]);
        if (fs::is_regular_file(p)) {
            key_files.push_back(p);
        } else if (query.empty()) {
            query = args[i];
        } else {
            throw std::invalid_argument("鍵ファイルが見つからないか、鍵 ID が 2 つ以上指定されています: " + args[i]);
        }
    }

    fs::path homedir = absolute_target(args[0]);
    std::vector<std::string> imported;
    if (!key_files.empty()) {
        // USB の直下などを指定されたときは、その中に gnupg フォルダを作って取り込む
        if (fs::is_directory(homedir) && !looks_like_gpg_homedir(homedir) && !fs::is_empty(homedir)) {
            homedir /= "gnupg";
        }
        std::cout << "鍵を取り込みます: " << display(homedir) << '\n';
        imported = import_gpg_keys(homedir, key_files);
    } else if (!fs::is_directory(homedir)) {
        throw std::runtime_error("フォルダが見つかりません: " + display(homedir));
    }

    std::vector<GpgKeyInfo> keys = find_gpg_secret_keys(homedir, query);
    if (!imported.empty()) {
        // 今回取り込んだ鍵だけを候補にする
        std::vector<GpgKeyInfo> filtered;
        for (auto& k : keys) {
            if (std::find(imported.begin(), imported.end(), k.fingerprint) != imported.end()) {
                filtered.push_back(std::move(k));
            }
        }
        keys = std::move(filtered);
    }
    if (keys.empty()) {
        if (!imported.empty()) {
            throw std::runtime_error(
                "取り込んだ鍵に、暗号化と署名の両方に使える秘密鍵がありません" +
                std::string(query.empty() ? "" : "（" + query + "）") +
                "\n公開鍵だけでは使えません。gpg --export-secret-keys で書き出した秘密鍵のファイルも指定してください");
        }
        throw std::runtime_error(
            "暗号化と署名の両方に使える GPG の秘密鍵が見つかりません" + (query.empty() ? "" : "（" + query + "）") +
            ": " + display(homedir) +
            "\n鍵ファイルを取り込むには:\n  ango gpg-setup '" + display(homedir) + "' 鍵ファイル..." +
            "\n新しく鍵を作るには、例えば次のようにします:\n  gpg --homedir '" + display(homedir) +
            "' --quick-generate-key '名前 <メール>' default default never");
    }
    if (keys.size() > 1) {
        std::string list;
        for (const auto& k : keys) {
            list += "\n  " + k.fingerprint + "  " + k.user_id;
        }
        throw std::runtime_error("使える鍵が複数あります。次のように鍵 ID（フィンガープリントなど）を指定してください:\n  ango gpg-setup '" +
                                 display(homedir) + "' 鍵ID" + list);
    }
    const GpgKeyInfo& key = keys.front();
    std::cout << "使う鍵: " << key.fingerprint << "  " << key.user_id << '\n';

    // 実際に暗号化・署名・復号できるか確かめる（ここでパスフレーズを尋ねることがある）
    GpgKeyOps ops(GpgKeyRef{homedir, key.fingerprint});
    SecureBuffer test_key(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    randombytes_buf(test_key.data(), test_key.size());
    const std::vector<unsigned char> wrapped = ops.wrap_file_key(test_key);
    const std::vector<unsigned char> sig = ops.sign(wrapped);
    ops.verify(wrapped, sig);
    const SecureBuffer unwrapped = ops.unwrap_file_key(wrapped);
    if (sodium_memcmp(unwrapped.data(), test_key.data(), test_key.size()) != 0) {
        throw std::runtime_error("GPG の鍵での試験に失敗しました（復号した内容が一致しません）");
    }

    const fs::path key_file = homedir / kGpgKeyFileName;
    clear_session(load_secret_key_location());  // ango の鍵の解錠キャッシュは不要になる
    write_gpg_key_file(key_file, key.fingerprint);
    save_secret_key_location(key_file);
    std::cout << "GPG の鍵を使うように設定しました: " << display(key_file) << "\n";
    disable_spotlight_indexing(key_file);
    std::cout << "\n"
              << "暗号化・復号のどちらにもこのフォルダ（USB）が必要です。GPG の秘密鍵はこのコンピュータに残さないでください。\n"
              << "ango の鍵 (ang_secret.key) に戻すには `ango key-location <ang_secret.key の場所>` を実行します。\n";
    for (const auto& f : key_files) {
        if (is_secret_key_file(f)) {
            std::cout << "\n注意: 取り込んだ秘密鍵のファイルが残っています。バックアップとして安全な場所へ移すか、削除してください:\n  "
                      << display(f) << '\n';
        }
    }
    return 0;
}

int cmd_lock(const std::vector<std::string>& args) {
    if (!args.empty()) {
        throw std::invalid_argument("lock に引数は要りません");
    }
    lock_all();
    std::cout << "ロックしました（次回はパスフレーズが必要です）\n";
    return 0;
}

// 鍵のあるディスクを取り外す（先にロックして、gpg のプロセスも止める）
int cmd_eject(const std::vector<std::string>& args) {
    if (!args.empty()) {
        throw std::invalid_argument("eject に引数は要りません");
    }
    const std::optional<fs::path> saved = load_secret_key_location();
    if (!saved) {
        throw std::runtime_error("秘密鍵の場所が保存されていないため、取り外すディスクが分かりません");
    }
    if (!fs::exists(*saved)) {
        lock_all();
        std::cout << "鍵が見つかりません（USB は既に取り外されているようです）。ロックしました\n";
        return 0;
    }
    const std::string mount_point = mount_point_of(*saved);
    lock_all();
    if (is_startup_volume(mount_point)) {
        std::cout << "ロックしました。鍵は起動ディスク上にあるため、取り外しはしません: " << display(*saved) << '\n';
        return 0;
    }
#ifdef __APPLE__
    // gpg のプロセスの終了や Spotlight の索引作成を待つことがあるので、しばらく試し続ける
    constexpr int kEjectAttempts = 10;
    for (int attempt = 1;; ++attempt) {
        const PipedResult r = run_piped({"/usr/sbin/diskutil", "eject", mount_point}, "");
        if (r.exit_code == 0) {
            std::cout << "ロックして取り外しました: " << mount_point << '\n';
            return 0;
        }
        const std::string out = r.out + r.err;
        const bool spotlight = out.find("mds") != std::string::npos;
        if (attempt == 1) {
            std::cerr << (spotlight ? "Spotlight が USB を使っているため、終わるのを待っています...\n"
                                    : "USB が使用中のため、少し待って再試行します...\n");
        }
        if (attempt >= kEjectAttempts) {
            std::string message = "ロックしましたが、取り外せませんでした: " + mount_point + "\n" + out;
            if (spotlight) {
                const bool marked = fs::exists(fs::symlink_status(fs::path(mount_point) / ".metadata_never_index"));
                message += "\nSpotlight（mds_stores）が USB の索引を作っているためです。少し待ってから `ango eject` を"
                           "やり直すか、次のコマンドでこの USB の索引作成を止めてください（初回のみ、管理者のパスワードが必要）:\n"
                           "  sudo mdutil -i off '" + mount_point + "'";
                if (!marked) {
                    message += "\nまたは、次のファイルを作っても止められます（macOS のバージョンによっては効きません）:\n"
                               "  touch '" + mount_point + "/.metadata_never_index'";
                }
            } else {
                int lsof_code = 0;
                const std::string users = run_capture({"lsof", "-w", "+f", "--", mount_point}, lsof_code);
                if (!users.empty()) {
                    message += "\n使用中のプロセス:\n" + users;
                }
            }
            throw std::runtime_error(message);
        }
        ::sleep(1);
    }
#else
    std::cout << "ロックしました。取り外しは OS の操作で行ってください: " << mount_point << '\n';
    return 0;
#endif
}

int run(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 2;
    }
    const std::string cmd = argv[1];
    const std::vector<std::string> args(argv + 2, argv + argc);

    if (cmd == "-h" || cmd == "--help" || cmd == "help") {
        print_usage();
        return 0;
    }
    if (cmd == "-V" || cmd == "--version") {
        std::cout << "ango " << ANG_VERSION << '\n';
        return 0;
    }
    if (cmd == "keygen") return cmd_keygen(args);
    if (cmd == "encrypt") return cmd_encrypt(args);
    if (cmd == "decrypt") return cmd_decrypt(args);
    if (cmd == "key-location") return cmd_key_location(args);
    if (cmd == "gpg-setup") return cmd_gpg_setup(args);
    if (cmd == "lock") return cmd_lock(args);
    if (cmd == "eject") return cmd_eject(args);

    std::cerr << "不明なコマンドです: " << cmd << "\n\n";
    print_usage();
    return 2;
}

}  // namespace
}  // namespace ang

int main(int argc, char** argv) {
    // tar が異常終了したときに SIGPIPE で落ちず、エラーとして扱う
    std::signal(SIGPIPE, SIG_IGN);
    try {
        ang::init_crypto();
        return ang::run(argc, argv);
    } catch (const ang::Cancelled& e) {
        std::cerr << e.what() << '\n';
        return 1;
    } catch (const std::invalid_argument& e) {
        std::cerr << "エラー: " << e.what() << "\n\n";
        ang::print_usage();
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "エラー: " << e.what() << '\n';
        ang::show_error(e.what());
        return 1;
    }
}
