#include "session.hpp"

#include "keystore.hpp"

#ifdef __APPLE__
#include <sys/sysctl.h>
#endif

#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace ang {

namespace {

// USB 側ファイル（秘密鍵の隣）:
//   "ANGSS" | version(1) | session_id | nonce | secretbox(pk || sk)
// PC 側ファイル（設定フォルダ）:
//   "ANGSP" | version(1) | session_id | K | expires_at(u64 LE, UNIX 秒)
// secretbox の鍵は BLAKE2b(key = K, "ang-session-v1" || session_id || 起動セッション ID)。
// 起動セッション ID を混ぜるので、再起動すると開けなくなる。
constexpr unsigned char kUsbMagic[5] = {'A', 'N', 'G', 'S', 'S'};
constexpr unsigned char kPcMagic[5] = {'A', 'N', 'G', 'S', 'P'};
constexpr unsigned char kSessionVersion = 1;
constexpr std::size_t kSessionIdBytes = 16;
constexpr std::size_t kSessionKeyBytes = 32;
constexpr std::size_t kKeyPairBytes = crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;

constexpr std::size_t kUsbFileSize = sizeof(kUsbMagic) + 1 + kSessionIdBytes + crypto_secretbox_NONCEBYTES +
                                     crypto_secretbox_MACBYTES + kKeyPairBytes;
constexpr std::size_t kPcFileSize = sizeof(kPcMagic) + 1 + kSessionIdBytes + kSessionKeyBytes + 8;

constexpr const char* kUsbFileName = "ang_session";
constexpr const char* kPcFileName = "session";

fs::path usb_file(const fs::path& secret_key_path) { return secret_key_path.parent_path() / kUsbFileName; }
fs::path pc_file() { return config_dir() / kPcFileName; }

std::uint64_t now_seconds() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}

std::uint64_t timeout_seconds() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(kSessionTimeout).count());
}

// 今回の起動を表す ID（再起動で変わる）
std::string boot_session_id() {
#ifdef __APPLE__
    char buf[64] = {};
    std::size_t len = sizeof(buf);
    if (::sysctlbyname("kern.bootsessionuuid", buf, &len, nullptr, 0) == 0) {
        return std::string(buf, ::strnlen(buf, sizeof(buf)));
    }
    return {};
#else
    std::ifstream in("/proc/sys/kernel/random/boot_id");
    std::string id;
    std::getline(in, id);
    return id;
#endif
}

SecureBuffer box_key(const unsigned char* k, const unsigned char* session_id) {
    static constexpr char kLabel[] = "ang-session-v1";
    const std::string boot = boot_session_id();
    std::vector<unsigned char> msg(kLabel, kLabel + sizeof(kLabel) - 1);
    msg.insert(msg.end(), session_id, session_id + kSessionIdBytes);
    msg.insert(msg.end(), boot.begin(), boot.end());

    SecureBuffer key(crypto_secretbox_KEYBYTES);
    crypto_generichash(key.data(), key.size(), msg.data(), msg.size(), k, kSessionKeyBytes);
    return key;
}

std::vector<unsigned char> pc_file_bytes(const unsigned char* session_id, const unsigned char* k,
                                         std::uint64_t expires_at) {
    std::vector<unsigned char> file;
    file.reserve(kPcFileSize);
    file.insert(file.end(), std::begin(kPcMagic), std::end(kPcMagic));
    file.push_back(kSessionVersion);
    file.insert(file.end(), session_id, session_id + kSessionIdBytes);
    file.insert(file.end(), k, k + kSessionKeyBytes);
    put_u64(file, expires_at);
    return file;
}

void remove_quietly(const fs::path& path) {
    std::error_code ec;
    fs::remove(path, ec);
}

}  // namespace

std::optional<KeyPair> load_session(const fs::path& secret_key_path) {
    const fs::path pc = pc_file();
    const fs::path usb = usb_file(secret_key_path);
    if (!fs::exists(pc)) {
        remove_quietly(usb);  // 対になる K が無いので使えない
        return std::nullopt;
    }

    try {
        std::vector<unsigned char> pc_data = read_small_file(pc, kPcFileSize);
        std::vector<unsigned char> usb_data = read_small_file(usb, kUsbFileSize);
        if (std::memcmp(pc_data.data(), kPcMagic, sizeof(kPcMagic)) != 0 ||
            pc_data[sizeof(kPcMagic)] != kSessionVersion ||
            std::memcmp(usb_data.data(), kUsbMagic, sizeof(kUsbMagic)) != 0 ||
            usb_data[sizeof(kUsbMagic)] != kSessionVersion) {
            throw std::runtime_error("形式が違う");
        }

        const unsigned char* pc_id = pc_data.data() + sizeof(kPcMagic) + 1;
        const unsigned char* k = pc_id + kSessionIdBytes;
        const std::uint64_t expires_at = get_u64(k + kSessionKeyBytes);
        const unsigned char* usb_id = usb_data.data() + sizeof(kUsbMagic) + 1;
        const unsigned char* nonce = usb_id + kSessionIdBytes;
        const unsigned char* cipher = nonce + crypto_secretbox_NONCEBYTES;

        const std::uint64_t now = now_seconds();
        if (now >= expires_at || expires_at > now + timeout_seconds() + 60) {
            throw std::runtime_error("期限切れ");
        }
        if (sodium_memcmp(pc_id, usb_id, kSessionIdBytes) != 0) {
            throw std::runtime_error("別のキャッシュ");
        }

        const SecureBuffer key = box_key(k, pc_id);
        SecureBuffer plain(kKeyPairBytes);
        if (crypto_secretbox_open_easy(plain.data(), cipher, crypto_secretbox_MACBYTES + kKeyPairBytes, nonce,
                                       key.data()) != 0) {
            throw std::runtime_error("開けない（再起動後など）");
        }

        KeyPair keys;
        std::memcpy(keys.pk.data(), plain.data(), crypto_box_PUBLICKEYBYTES);
        std::memcpy(keys.sk.data(), plain.data() + crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES);
        derive_signing_keys(keys);

        // 使ったので有効期限を延長する
        std::vector<unsigned char> renewed = pc_file_bytes(pc_id, k, now + timeout_seconds());
        sodium_memzero(pc_data.data(), pc_data.size());
        replace_file(pc, renewed, 0600);
        sodium_memzero(renewed.data(), renewed.size());
        return keys;
    } catch (const std::exception&) {
        // 無効なキャッシュは消してパスフレーズを聞き直す（USB が無ければ USB 側は残るが、K が無いので開けない）
        remove_quietly(pc);
        remove_quietly(usb);
        return std::nullopt;
    }
}

void create_session(const fs::path& secret_key_path, const KeyPair& keys) {
    unsigned char session_id[kSessionIdBytes];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    SecureBuffer k(kSessionKeyBytes);
    randombytes_buf(session_id, sizeof(session_id));
    randombytes_buf(nonce, sizeof(nonce));
    randombytes_buf(k.data(), k.size());

    SecureBuffer plain(kKeyPairBytes);
    std::memcpy(plain.data(), keys.pk.data(), crypto_box_PUBLICKEYBYTES);
    std::memcpy(plain.data() + crypto_box_PUBLICKEYBYTES, keys.sk.data(), crypto_box_SECRETKEYBYTES);
    const SecureBuffer key = box_key(k.data(), session_id);

    std::vector<unsigned char> usb_data;
    usb_data.reserve(kUsbFileSize);
    usb_data.insert(usb_data.end(), std::begin(kUsbMagic), std::end(kUsbMagic));
    usb_data.push_back(kSessionVersion);
    usb_data.insert(usb_data.end(), std::begin(session_id), std::end(session_id));
    usb_data.insert(usb_data.end(), std::begin(nonce), std::end(nonce));
    usb_data.resize(kUsbFileSize);
    crypto_secretbox_easy(usb_data.data() + (kUsbFileSize - crypto_secretbox_MACBYTES - kKeyPairBytes), plain.data(),
                          plain.size(), nonce, key.data());

    std::vector<unsigned char> pc_data = pc_file_bytes(session_id, k.data(), now_seconds() + timeout_seconds());
    try {
        replace_file(usb_file(secret_key_path), usb_data, 0600);
        replace_file(pc_file(), pc_data, 0600);
    } catch (const std::exception& e) {
        clear_session(secret_key_path);
        std::cerr << "警告: 解錠キャッシュを作れませんでした（次回もパスフレーズが必要です）: " << e.what() << '\n';
    }
    sodium_memzero(pc_data.data(), pc_data.size());
}

void clear_session(const std::optional<fs::path>& secret_key_path) {
    remove_quietly(pc_file());
    if (secret_key_path) {
        remove_quietly(usb_file(*secret_key_path));
    }
}

}  // namespace ang
