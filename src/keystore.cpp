#include "keystore.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>

namespace ang {

namespace {

// 秘密鍵ファイル形式:
//   "ANGSK" | version(1) | salt | opslimit(u64 LE) | memlimit(u64 LE) | nonce | secretbox(pk || sk)
constexpr unsigned char kSecretMagic[5] = {'A', 'N', 'G', 'S', 'K'};
constexpr unsigned char kKeyFileVersion = 1;

constexpr std::size_t kKeyPairBytes = crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
constexpr std::size_t kSecretFileSize = sizeof(kSecretMagic) + 1 + crypto_pwhash_SALTBYTES + 8 + 8 +
                                        crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + kKeyPairBytes;

// 読み込み時に受け付けるパスワードハッシュのコスト上限（壊れたファイルで過大なメモリを要求されないように）
constexpr unsigned long long kMaxOpsLimit = crypto_pwhash_OPSLIMIT_SENSITIVE;
constexpr std::size_t kMaxMemLimit = crypto_pwhash_MEMLIMIT_SENSITIVE;

constexpr const char* kLocationFileName = "secret_key_location";

fs::path home_dir() {
    const char* home = std::getenv("HOME");
    if (home == nullptr || *home == '\0') {
        throw std::runtime_error("HOME 環境変数が設定されていません");
    }
    return fs::path(home);
}

}  // namespace

void put_u64(std::vector<unsigned char>& buf, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

std::uint64_t get_u64(const unsigned char* p) {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(p[i]) << (8 * i);
    }
    return value;
}

void write_new_file(const fs::path& path, const std::vector<unsigned char>& data, unsigned int mode) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) {
        throw std::runtime_error("ファイルを作成できません: " + path.string() + ": " + std::strerror(errno));
    }
    std::size_t written = 0;
    while (written < data.size()) {
        const ssize_t n = ::write(fd, data.data() + written, data.size() - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            const int err = errno;
            ::close(fd);
            ::unlink(path.c_str());
            throw std::runtime_error("書き込みに失敗しました: " + path.string() + ": " + std::strerror(err));
        }
        written += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0 || ::close(fd) != 0) {
        throw std::runtime_error("書き込みに失敗しました: " + path.string() + ": " + std::strerror(errno));
    }
}

std::vector<unsigned char> read_small_file(const fs::path& path, std::size_t expected_size) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("ファイルを開けません: " + path.string());
    }
    std::vector<unsigned char> data(expected_size + 1);
    in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (static_cast<std::size_t>(in.gcount()) != expected_size) {
        throw std::runtime_error("鍵ファイルの形式が正しくありません: " + path.string());
    }
    data.resize(expected_size);
    return data;
}

void replace_file(const fs::path& path, const std::vector<unsigned char>& data, unsigned int mode) {
    unsigned char rnd[6];
    randombytes_buf(rnd, sizeof(rnd));
    char hex[sizeof(rnd) * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), rnd, sizeof(rnd));
    const fs::path tmp = path.parent_path() / ("." + path.filename().string() + ".tmp-" + hex);
    write_new_file(tmp, data, mode);
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        fs::remove(tmp, ec);
        throw std::runtime_error("ファイルを置き換えられません: " + path.string());
    }
}

void write_secret_key_file(const fs::path& path, const KeyPair& keys, const std::string& passphrase) {
    const unsigned long long opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
    const std::size_t memlimit = crypto_pwhash_MEMLIMIT_MODERATE;

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(salt, sizeof(salt));
    randombytes_buf(nonce, sizeof(nonce));

    SecureBuffer wrap_key(crypto_secretbox_KEYBYTES);
    if (crypto_pwhash(wrap_key.data(), wrap_key.size(), passphrase.data(), passphrase.size(), salt, opslimit,
                      memlimit, crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw CryptoError("パスフレーズからの鍵生成に失敗しました（メモリ不足）");
    }

    SecureBuffer plain(kKeyPairBytes);
    std::memcpy(plain.data(), keys.pk.data(), crypto_box_PUBLICKEYBYTES);
    std::memcpy(plain.data() + crypto_box_PUBLICKEYBYTES, keys.sk.data(), crypto_box_SECRETKEYBYTES);

    std::vector<unsigned char> cipher(crypto_secretbox_MACBYTES + kKeyPairBytes);
    crypto_secretbox_easy(cipher.data(), plain.data(), plain.size(), nonce, wrap_key.data());

    std::vector<unsigned char> file;
    file.reserve(kSecretFileSize);
    file.insert(file.end(), std::begin(kSecretMagic), std::end(kSecretMagic));
    file.push_back(kKeyFileVersion);
    file.insert(file.end(), std::begin(salt), std::end(salt));
    put_u64(file, opslimit);
    put_u64(file, memlimit);
    file.insert(file.end(), std::begin(nonce), std::end(nonce));
    file.insert(file.end(), cipher.begin(), cipher.end());

    write_new_file(path, file, 0600);
}

KeyPair read_secret_key_file(const fs::path& path, const std::string& passphrase) {
    const std::vector<unsigned char> file = read_small_file(path, kSecretFileSize);
    if (std::memcmp(file.data(), kSecretMagic, sizeof(kSecretMagic)) != 0 ||
        file[sizeof(kSecretMagic)] != kKeyFileVersion) {
        throw std::runtime_error("Ango の秘密鍵ファイルではありません: " + path.string());
    }

    const unsigned char* p = file.data() + sizeof(kSecretMagic) + 1;
    const unsigned char* salt = p;
    p += crypto_pwhash_SALTBYTES;
    const std::uint64_t opslimit = get_u64(p);
    p += 8;
    const std::uint64_t memlimit = get_u64(p);
    p += 8;
    const unsigned char* nonce = p;
    p += crypto_secretbox_NONCEBYTES;
    const unsigned char* cipher = p;

    if (opslimit < crypto_pwhash_OPSLIMIT_MIN || opslimit > kMaxOpsLimit || memlimit < crypto_pwhash_MEMLIMIT_MIN ||
        memlimit > kMaxMemLimit) {
        throw std::runtime_error("秘密鍵ファイルのパラメータが不正です: " + path.string());
    }

    SecureBuffer wrap_key(crypto_secretbox_KEYBYTES);
    if (crypto_pwhash(wrap_key.data(), wrap_key.size(), passphrase.data(), passphrase.size(), salt, opslimit,
                      static_cast<std::size_t>(memlimit), crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw CryptoError("パスフレーズからの鍵生成に失敗しました（メモリ不足）");
    }

    SecureBuffer plain(kKeyPairBytes);
    if (crypto_secretbox_open_easy(plain.data(), cipher, crypto_secretbox_MACBYTES + kKeyPairBytes, nonce,
                                   wrap_key.data()) != 0) {
        throw WrongPassphrase();
    }

    KeyPair keys;
    std::memcpy(keys.pk.data(), plain.data(), crypto_box_PUBLICKEYBYTES);
    std::memcpy(keys.sk.data(), plain.data() + crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES);

    PublicKey derived{};
    crypto_scalarmult_base(derived.data(), keys.sk.data());
    if (sodium_memcmp(derived.data(), keys.pk.data(), derived.size()) != 0) {
        throw std::runtime_error("秘密鍵ファイルの内容が矛盾しています: " + path.string());
    }
    derive_signing_keys(keys);
    return keys;
}

fs::path config_dir() {
#ifdef __APPLE__
    fs::path dir = home_dir() / "Library" / "Application Support" / "ang";
#else
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    fs::path dir = (xdg != nullptr && *xdg != '\0') ? fs::path(xdg) / "ang" : home_dir() / ".config" / "ang";
#endif
    if (!fs::exists(dir)) {
        fs::create_directories(dir);
        fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace);
    }
    return dir;
}

std::optional<fs::path> load_secret_key_location() {
    std::ifstream in(config_dir() / kLocationFileName);
    std::string line;
    if (!in || !std::getline(in, line) || line.empty()) {
        return std::nullopt;
    }
    return fs::path(line);
}

void save_secret_key_location(const fs::path& path) {
    const fs::path file = config_dir() / kLocationFileName;
    std::ofstream out(file, std::ios::trunc);
    out << fs::absolute(path).lexically_normal().string() << '\n';
    if (!out) {
        throw std::runtime_error("鍵の場所を保存できません: " + file.string());
    }
}

void forget_secret_key_location() {
    std::error_code ec;
    fs::remove(config_dir() / kLocationFileName, ec);
}

fs::path normalize_user_path(const std::string& input) {
    std::string s = input;
    // 前後の空白
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    s = s.substr(first, s.find_last_not_of(" \t\r\n") - first + 1);

    // 'path' または "path"
    if (s.size() >= 2 && (s.front() == '\'' || s.front() == '"') && s.back() == s.front()) {
        s = s.substr(1, s.size() - 2);
    } else {
        // ドラッグ&ドロップで付く "\ " などのエスケープを外す
        std::string unescaped;
        for (std::size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '\\' && i + 1 < s.size()) {
                ++i;
            }
            unescaped += s[i];
        }
        s = unescaped;
    }

    if (s == "~") {
        return home_dir();
    }
    if (s.rfind("~/", 0) == 0) {
        return home_dir() / s.substr(2);
    }
    return fs::path(s);
}

}  // namespace ang
