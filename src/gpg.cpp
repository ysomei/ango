#include "gpg.hpp"

#include "keystore.hpp"
#include "prompt.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

namespace ang {

namespace {

// ang_gpg.key の形式（テキスト）:
//   ANG-GPG-KEY 1
//   fingerprint=<主鍵のフィンガープリント>
constexpr const char* kGpgKeyFileHeader = "ANG-GPG-KEY 1";

// gpg のエラーコード（libgpg-error、下位 16 ビット）
constexpr unsigned kGpgErrBadPassphrase = 11;
constexpr unsigned kGpgErrNoPinentry = 85;

constexpr int kPassphraseAttempts = 3;

// gpg-agent などのソケット名。GNUPGHOME 内に作れない（exFAT/FAT の USB、パスが長すぎる）ことがあるので、
// GnuPG の「ソケットの転送」機能で PC 側の一時フォルダへ移す
constexpr const char* kSocketNames[] = {
    "S.gpg-agent", "S.gpg-agent.extra", "S.gpg-agent.browser", "S.gpg-agent.ssh",
    "S.scdaemon",  "S.keyboxd",         "S.dirmngr",
};
constexpr std::size_t kMaxSocketPath = 100;  // macOS の sun_path は 104 バイト

bool is_executable(const fs::path& p) { return ::access(p.c_str(), X_OK) == 0 && fs::is_regular_file(p); }

// gpg の場所。Finder から起動されたときは PATH が短いので、よくある場所も探す
fs::path gpg_program() {
    if (const char* env = std::getenv("ANGO_GPG"); env != nullptr && *env != '\0') {
        return env;
    }
    std::vector<fs::path> candidates;
    if (const char* path = std::getenv("PATH"); path != nullptr) {
        std::stringstream ss(path);
        std::string dir;
        while (std::getline(ss, dir, ':')) {
            if (!dir.empty()) candidates.push_back(fs::path(dir) / "gpg");
        }
    }
    for (const char* p : {"/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/local/MacGPG2/bin/gpg"}) {
        candidates.emplace_back(p);
    }
    for (const auto& c : candidates) {
        if (is_executable(c)) return c;
    }
    throw std::runtime_error(
        "gpg が見つかりません。GnuPG をインストールしてください（例: brew install gnupg）。"
        "環境変数 ANGO_GPG で gpg の場所を指定することもできます");
}

fs::path gpgconf_program() {
    const fs::path gpg = gpg_program();
    const fs::path next_to = gpg.parent_path() / "gpgconf";
    return is_executable(next_to) ? next_to : fs::path("gpgconf");
}

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> lines;
    std::stringstream ss(s);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
    }
    return lines;
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> fields;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            fields.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    fields.push_back(cur);
    return fields;
}

// --status-fd 2 で標準エラーに混ざる "[GNUPG:] KEYWORD args..." を取り出す
std::vector<std::vector<std::string>> status_lines(const std::string& err) {
    static constexpr char kPrefix[] = "[GNUPG:] ";
    std::vector<std::vector<std::string>> result;
    for (const auto& line : split_lines(err)) {
        if (line.rfind(kPrefix, 0) != 0) continue;
        std::vector<std::string> words;
        for (const auto& w : split(line.substr(sizeof(kPrefix) - 1), ' ')) {
            if (!w.empty()) words.push_back(w);
        }
        if (!words.empty()) result.push_back(std::move(words));
    }
    return result;
}

bool has_error_code(const std::string& err, unsigned code) {
    for (const auto& st : status_lines(err)) {
        if ((st[0] == "ERROR" || st[0] == "FAILURE") && st.size() >= 3) {
            const unsigned long value = std::strtoul(st[2].c_str(), nullptr, 10);
            if ((value & 0xFFFFu) == code) return true;
        }
    }
    return false;
}

// 利用者向けのメッセージ（ステータス行を除いた gpg の出力）
std::string gpg_messages(const std::string& err) {
    std::string msg;
    for (const auto& line : split_lines(err)) {
        if (line.rfind("[GNUPG:]", 0) == 0 || line.empty()) continue;
        msg += "\n  " + line;
    }
    return msg;
}

std::runtime_error gpg_failure(const std::string& what, const PipedResult& r) {
    return std::runtime_error("GPG で" + what + "できませんでした（終了コード " + std::to_string(r.exit_code) + "）" +
                              gpg_messages(r.err));
}

std::string upper(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

bool is_fingerprint(const std::string& s) {
    if (s.size() != 40 && s.size() != 64) return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

// ソケットを置く PC 側のフォルダ（利用者ごと・GNUPGHOME ごと）
fs::path socket_dir(const fs::path& homedir) {
    fs::path base;
#ifdef __APPLE__
    char buf[PATH_MAX];
    if (::confstr(_CS_DARWIN_USER_TEMP_DIR, buf, sizeof(buf)) > 0) {
        base = buf;
    }
#else
    if (const char* xdg = std::getenv("XDG_RUNTIME_DIR"); xdg != nullptr && *xdg != '\0') {
        base = xdg;
    }
#endif
    const std::string user_dir = "ango-gpg-" + std::to_string(::getuid());
    const std::string canonical = fs::weakly_canonical(homedir).string();
    unsigned char hash[8];
    crypto_generichash(hash, sizeof(hash), reinterpret_cast<const unsigned char*>(canonical.data()),
                       canonical.size(), nullptr, 0);
    char hex[sizeof(hash) * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), hash, sizeof(hash));

    fs::path dir = base / user_dir;
    if (base.empty() || (dir / hex / "S.gpg-agent.browser").string().size() > kMaxSocketPath) {
        dir = fs::path("/tmp") / user_dir;
    }

    // 他人が先に作ったフォルダやシンボリックリンクは使わない
    for (const fs::path& d : {dir, dir / hex}) {
        if (::mkdir(d.c_str(), 0700) != 0 && errno != EEXIST) {
            throw std::runtime_error("フォルダを作成できません: " + d.string() + ": " + std::strerror(errno));
        }
        struct stat st {};
        if (::lstat(d.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::getuid() ||
            (st.st_mode & 0077) != 0) {
            throw std::runtime_error("gpg 用の一時フォルダが安全ではありません: " + d.string());
        }
    }
    return dir / hex;
}

std::string read_text(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// GNUPGHOME にソケットの転送ファイルを用意する。
// gpg-agent が GNUPGHOME 内に本物のソケットを作っている（作れる場所で、既に動いている）ならそのまま使う
void prepare_homedir(const fs::path& homedir) {
    if (!fs::is_directory(homedir)) {
        throw std::runtime_error("GPG のフォルダが見つかりません。USB を差してから、もう一度実行してください。\n  " +
                                 homedir.string());
    }
    std::error_code ec;
    if (fs::is_socket(fs::symlink_status(homedir / "S.gpg-agent", ec))) {
        return;
    }
    const fs::path dir = socket_dir(homedir);
    for (const char* name : kSocketNames) {
        const fs::path file = homedir / name;
        if (fs::is_socket(fs::symlink_status(file, ec))) continue;
        const std::string content = "%Assuan%\nsocket=" + (dir / name).string() + "\n";
        if (fs::is_regular_file(file, ec) && read_text(file) == content) continue;
        replace_file(file, std::vector<unsigned char>(content.begin(), content.end()), 0600);
    }
}

std::vector<std::string> base_args(const fs::path& homedir) {
    return {gpg_program().string(), "--homedir", homedir.string(), "--batch", "--no-tty", "--quiet",
            "--no-greeting", "--status-fd", "2", "--no-auto-key-retrieve", "--trust-model", "always"};
}

std::string to_string(const std::vector<unsigned char>& v) { return std::string(v.begin(), v.end()); }

}  // namespace

// ---------------------------------------------------------------- 設定ファイル

bool is_gpg_key_file(const fs::path& path) {
    std::ifstream in(path);
    std::string line;
    return in && std::getline(in, line) && line == kGpgKeyFileHeader;
}

GpgKeyRef read_gpg_key_file(const fs::path& path) {
    std::ifstream in(path);
    std::string line;
    if (!in || !std::getline(in, line) || line != kGpgKeyFileHeader) {
        throw std::runtime_error("GPG の鍵の設定ファイルではありません: " + path.string());
    }
    GpgKeyRef ref;
    ref.homedir = fs::absolute(path).lexically_normal().parent_path();
    while (std::getline(in, line)) {
        static constexpr char kKey[] = "fingerprint=";
        if (line.rfind(kKey, 0) == 0) {
            ref.fingerprint = upper(line.substr(sizeof(kKey) - 1));
        }
    }
    if (!is_fingerprint(ref.fingerprint)) {
        throw std::runtime_error("GPG の鍵の設定ファイルにフィンガープリントがありません: " + path.string());
    }
    return ref;
}

void write_gpg_key_file(const fs::path& path, const std::string& fingerprint) {
    const std::string content = std::string(kGpgKeyFileHeader) + "\nfingerprint=" + fingerprint + "\n";
    replace_file(path, std::vector<unsigned char>(content.begin(), content.end()), 0600);
}

bool looks_like_gpg_homedir(const fs::path& dir) {
    std::error_code ec;
    return fs::exists(dir / "pubring.kbx", ec) || fs::exists(dir / "pubring.gpg", ec) ||
           fs::is_directory(dir / "private-keys-v1.d", ec);
}

std::vector<std::string> import_gpg_keys(const fs::path& homedir, const std::vector<fs::path>& files) {
    if (!fs::exists(homedir)) {
        fs::create_directories(homedir.parent_path());
        if (::mkdir(homedir.c_str(), 0700) != 0) {
            throw std::runtime_error("フォルダを作成できません: " + homedir.string() + ": " + std::strerror(errno));
        }
    }
    prepare_homedir(homedir);
    std::vector<std::string> args = base_args(homedir);
    args.push_back("--import");
    args.push_back("--");
    for (const auto& f : files) args.push_back(f.string());
    const PipedResult r = run_piped(args, "");
    std::vector<std::string> fprs;
    for (const auto& st : status_lines(r.err)) {
        // IMPORT_OK <理由> <フィンガープリント>
        if (st[0] == "IMPORT_OK" && st.size() >= 3) {
            const std::string fpr = upper(st[2]);
            if (is_fingerprint(fpr) && std::find(fprs.begin(), fprs.end(), fpr) == fprs.end()) fprs.push_back(fpr);
        }
    }
    if (fprs.empty()) {
        throw gpg_failure("鍵を取り込み", r);
    }
    if (r.exit_code != 0) {
        std::cerr << "警告: 取り込めなかった鍵があります" << gpg_messages(r.err) << '\n';
    }
    return fprs;
}

bool is_secret_key_file(const fs::path& path) {
    std::ifstream in(path);
    std::string line;
    for (int i = 0; i < 5 && std::getline(in, line); ++i) {
        if (line.rfind("-----BEGIN PGP PRIVATE KEY BLOCK-----", 0) == 0) return true;
    }
    return false;
}

std::vector<GpgKeyInfo> find_gpg_secret_keys(const fs::path& homedir, const std::string& query) {
    prepare_homedir(homedir);
    std::vector<std::string> args = base_args(homedir);
    for (const char* a : {"--with-colons", "--fixed-list-mode", "--list-secret-keys"}) args.emplace_back(a);
    if (!query.empty()) {
        args.push_back("--");
        args.push_back(query);
    }
    const PipedResult r = run_piped(args, "");
    if (r.exit_code != 0 && !query.empty()) {
        return {};  // 一致する鍵がない
    }
    if (r.exit_code != 0) {
        throw gpg_failure("鍵の一覧を取得", r);
    }

    // sec（主鍵）ごとに、利用可能な機能（12 番目の欄の大文字 E/S）とフィンガープリント・ユーザー ID を集める
    std::vector<GpgKeyInfo> keys;
    bool in_usable_key = false;
    bool want_fpr = false;
    for (const auto& line : split_lines(r.out)) {
        const std::vector<std::string> f = split(line, ':');
        if (f.empty()) continue;
        if (f[0] == "sec") {
            const std::string validity = f.size() > 1 ? f[1] : "";
            const std::string caps = f.size() > 11 ? f[11] : "";
            in_usable_key = validity != "r" && validity != "e" && validity != "d" && validity != "i" &&
                            caps.find('E') != std::string::npos && caps.find('S') != std::string::npos;
            want_fpr = in_usable_key;
            if (in_usable_key) keys.push_back({});
        } else if (f[0] == "ssb") {
            want_fpr = false;
        } else if (f[0] == "fpr" && want_fpr && f.size() > 9) {
            keys.back().fingerprint = upper(f[9]);
            want_fpr = false;
        } else if (f[0] == "uid" && in_usable_key && keys.back().user_id.empty() && f.size() > 9) {
            keys.back().user_id = f[9];
        }
    }
    std::vector<GpgKeyInfo> usable;
    for (auto& k : keys) {
        if (is_fingerprint(k.fingerprint)) usable.push_back(std::move(k));
    }
    return usable;
}

void gpg_forget_passphrase(const fs::path& homedir) {
    if (!fs::is_directory(homedir)) return;
    try {
        const PipedResult r = run_piped({gpgconf_program().string(), "--homedir", homedir.string(), "--kill", "all"}, "");
        if (r.exit_code != 0) {
            std::cerr << "警告: gpg のプロセスを止められませんでした" << gpg_messages(r.err) << '\n';
        }
    } catch (const std::exception& e) {
        std::cerr << "警告: gpg-agent を止められませんでした: " << e.what() << '\n';
    }
}

// ---------------------------------------------------------------- GpgKeyOps

GpgKeyOps::GpgKeyOps(GpgKeyRef ref) : ref_(std::move(ref)) { prepare_homedir(ref_.homedir); }

GpgKeyOps::~GpgKeyOps() {
    if (passphrase_) sodium_memzero(passphrase_->data(), passphrase_->size());
}

PipedResult GpgKeyOps::run(const std::vector<std::string>& args, const std::string& input, const std::string* fd3) {
    std::vector<std::string> argv = base_args(ref_.homedir);
    argv.insert(argv.end(), args.begin(), args.end());
    return run_piped(argv, input, fd3);
}

PipedResult GpgKeyOps::run_with_secret(const std::vector<std::string>& args, const std::string& input,
                                       const char* what) {
    // まず尋ねずに試す（gpg-agent が覚えている、パスフレーズのない鍵、など）
    std::vector<std::string> quiet{"--pinentry-mode", "error"};
    quiet.insert(quiet.end(), args.begin(), args.end());
    PipedResult r = run(quiet, input, nullptr);
    if (r.exit_code == 0) return r;
    if (!has_error_code(r.err, kGpgErrNoPinentry)) throw gpg_failure(what, r);

    // ango が尋ねて gpg に渡す（gpg-agent が覚えるので、次からは尋ねない）
    std::vector<std::string> loopback{"--pinentry-mode", "loopback", "--passphrase-fd", "3"};
    loopback.insert(loopback.end(), args.begin(), args.end());
    for (int attempt = 1;;) {
        std::string pass;
        const bool reuse = passphrase_.has_value();
        if (reuse) {
            pass = *passphrase_;
        } else {
            std::optional<std::string> answer = ask_passphrase("GPG の秘密鍵のパスフレーズを入力してください: ");
            if (!answer) throw Cancelled();
            pass = std::move(*answer);
        }
        r = run(loopback, input, &pass);
        if (r.exit_code == 0) {
            if (!reuse) passphrase_ = pass;
            sodium_memzero(pass.data(), pass.size());
            return r;
        }
        sodium_memzero(pass.data(), pass.size());
        if (!has_error_code(r.err, kGpgErrBadPassphrase)) throw gpg_failure(what, r);
        if (reuse) {
            sodium_memzero(passphrase_->data(), passphrase_->size());
            passphrase_.reset();
            continue;
        }
        if (attempt++ >= kPassphraseAttempts) throw WrongPassphrase();
        std::cerr << "パスフレーズが違います。もう一度入力してください。\n";
    }
}

std::vector<unsigned char> GpgKeyOps::wrap_file_key(const SecureBuffer& file_key) {
    std::string input(reinterpret_cast<const char*>(file_key.data()), file_key.size());
    PipedResult r = run({"--no-encrypt-to", "--compress-algo", "none", "--encrypt", "--recipient", ref_.fingerprint,
                         "--output", "-"},
                        input, nullptr);
    sodium_memzero(input.data(), input.size());
    if (r.exit_code != 0 || r.out.empty()) throw gpg_failure("ファイル鍵を暗号化", r);
    return std::vector<unsigned char>(r.out.begin(), r.out.end());
}

SecureBuffer GpgKeyOps::unwrap_file_key(const std::vector<unsigned char>& wrapped) {
    PipedResult r = run_with_secret({"--decrypt", "--output", "-"}, to_string(wrapped), "ファイル鍵を復号");
    bool ours = false;
    for (const auto& st : status_lines(r.err)) {
        // DECRYPTION_KEY <使った鍵> <主鍵> <信用度>
        if (st[0] == "DECRYPTION_KEY" && st.size() >= 3 && upper(st[2]) == ref_.fingerprint) ours = true;
    }
    SecureBuffer key(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    const bool ok = ours && r.out.size() == key.size();
    if (ok) std::memcpy(key.data(), r.out.data(), key.size());
    sodium_memzero(r.out.data(), r.out.size());
    if (!ok) {
        throw CryptoError("復号できません（指定の GPG の鍵で暗号化されたファイルではないか、ファイルが壊れています）");
    }
    return key;
}

std::vector<unsigned char> GpgKeyOps::sign(const std::vector<unsigned char>& message) {
    PipedResult r =
        run_with_secret({"--detach-sign", "--local-user", ref_.fingerprint, "--output", "-"}, to_string(message),
                        "署名");
    if (r.out.empty()) throw gpg_failure("署名", r);
    return std::vector<unsigned char>(r.out.begin(), r.out.end());
}

void GpgKeyOps::verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature) {
    // 署名はファイル記述子 3 から、署名対象は標準入力から渡す
    const std::string sig = to_string(signature);
    const PipedResult r = run({"--enable-special-filenames", "--verify", "--", "-&3", "-"}, to_string(message), &sig);
    int signatures = 0;
    bool valid = false;
    bool bad = false;
    for (const auto& st : status_lines(r.err)) {
        if (st[0] == "NEWSIG") ++signatures;
        if (st[0] == "BADSIG" || st[0] == "ERRSIG") bad = true;
        // VALIDSIG <署名した鍵> ... <主鍵>（最後の欄）
        if (st[0] == "VALIDSIG" && st.size() >= 11 && upper(st.back()) == ref_.fingerprint) valid = true;
    }
    if (r.exit_code != 0 || signatures != 1 || bad || !valid) {
        throw CryptoError("署名が一致しません（指定の GPG の鍵で作られたファイルではないか、改ざんされています）");
    }
}

}  // namespace ang
