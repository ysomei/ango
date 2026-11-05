#include "crypto.hpp"

#include <cerrno>
#include <cstring>
#include <new>
#include <vector>

namespace ang {

namespace {

// ファイル形式:
//   version 1, 2（ango の鍵）:
//     "ANGF" | version(1) | kind(1) | sealed_key(80) | stream_header(24) | [signature(64)] | chunk...
//   version 3（GPG の鍵）:
//     "ANGF" | 3 | kind(1) | len(u32 LE) | wrapped_key(len) | stream_header(24) | len(u32 LE) | signature(len) | chunk...
//     wrapped_key はファイル鍵を gpg で暗号化した OpenPGP メッセージ、signature は gpg の分離署名
// signature（version 2 以降）は signature（v3 はその長さ）より前の全バイトに対する署名。
// 本文の chunk はヘッダー内のファイル鍵でしか作れないので、ヘッダーへの署名で本文も作成者に結び付く。
// 各 chunk は crypto_secretstream_xchacha20poly1305 で暗号化され、最後の chunk に TAG_FINAL が付く。
constexpr unsigned char kMagic[4] = {'A', 'N', 'G', 'F'};
constexpr std::size_t kChunkSize = 64 * 1024;
constexpr std::size_t kSealedKeyBytes = crypto_box_SEALBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES;
// v3 の可変長部分の上限（壊れたファイルで過大なメモリを要求されないように）
constexpr std::uint32_t kMaxGpgBlobBytes = 64 * 1024;

// 署名鍵の導出に使う文脈（crypto_kdf_CONTEXTBYTES = 8 文字）
constexpr char kSignKdfContext[crypto_kdf_CONTEXTBYTES + 1] = "angsign1";
constexpr std::uint64_t kSignKdfId = 1;

void put_u32(std::vector<unsigned char>& buf, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        buf.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

std::uint32_t read_u32(std::FILE* in, const char* what) {
    unsigned char b[4];
    read_exact(in, b, sizeof(b), what);
    return static_cast<std::uint32_t>(b[0]) | (static_cast<std::uint32_t>(b[1]) << 8) |
           (static_cast<std::uint32_t>(b[2]) << 16) | (static_cast<std::uint32_t>(b[3]) << 24);
}

std::vector<unsigned char> read_blob(std::FILE* in, const char* what) {
    const std::uint32_t len = read_u32(in, what);
    if (len == 0 || len > kMaxGpgBlobBytes) {
        throw CryptoError(std::string("暗号化ファイルが壊れています（") + what + " の長さが不正）");
    }
    std::vector<unsigned char> blob(len);
    read_exact(in, blob.data(), blob.size(), what);
    return blob;
}

// 署名の対象（signature より前の部分）
std::vector<unsigned char> signed_part(const EncryptedHeader& h) {
    std::vector<unsigned char> buf;
    buf.reserve(sizeof(kMagic) + 2 + 4 + h.wrapped_key.size() + h.stream_header.size());
    buf.insert(buf.end(), std::begin(kMagic), std::end(kMagic));
    buf.push_back(h.version);
    buf.push_back(static_cast<unsigned char>(h.kind));
    if (h.version == kFormatGpg) {
        put_u32(buf, static_cast<std::uint32_t>(h.wrapped_key.size()));
    }
    buf.insert(buf.end(), h.wrapped_key.begin(), h.wrapped_key.end());
    buf.insert(buf.end(), h.stream_header.begin(), h.stream_header.end());
    return buf;
}

std::string mismatch_message(unsigned char file_version) {
    if (file_version == kFormatGpg) {
        return "このファイルは GPG の鍵で暗号化されています。"
               "`ango key-location` で GPG の鍵の設定ファイル (ang_gpg.key) を指定してください";
    }
    return "このファイルは ango の鍵 (ang_secret.key) で暗号化されています。"
           "`ango key-location` で ang_secret.key を指定してください";
}

}  // namespace

bool EncryptedHeader::is_signed() const { return version >= kFormatSodium; }

SecureBuffer::SecureBuffer(std::size_t size)
    : data_(static_cast<unsigned char*>(sodium_malloc(size))), size_(size) {
    if (data_ == nullptr) {
        throw std::bad_alloc();
    }
}

SecureBuffer::~SecureBuffer() { sodium_free(data_); }

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        sodium_free(data_);
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

void init_crypto() {
    if (sodium_init() < 0) {
        throw CryptoError("libsodium の初期化に失敗しました");
    }
}

KeyPair generate_keypair() {
    KeyPair keys;
    crypto_box_keypair(keys.pk.data(), keys.sk.data());
    derive_signing_keys(keys);
    return keys;
}

void derive_signing_keys(KeyPair& keys) {
    static_assert(crypto_box_SECRETKEYBYTES == crypto_kdf_KEYBYTES, "sk は KDF の鍵として使う");
    SecureBuffer seed(crypto_sign_SEEDBYTES);
    crypto_kdf_derive_from_key(seed.data(), seed.size(), kSignKdfId, kSignKdfContext, keys.sk.data());
    crypto_sign_seed_keypair(keys.sign_pk.data(), keys.sign_sk.data(), seed.data());
}

void write_all(std::FILE* out, const void* data, std::size_t size) {
    if (size > 0 && std::fwrite(data, 1, size, out) != size) {
        throw std::runtime_error(std::string("書き込みに失敗しました: ") + std::strerror(errno));
    }
}

void read_exact(std::FILE* in, void* data, std::size_t size, const char* what) {
    if (std::fread(data, 1, size, in) != size) {
        if (std::ferror(in)) {
            throw std::runtime_error(std::string("読み込みに失敗しました: ") + std::strerror(errno));
        }
        throw CryptoError(std::string("暗号化ファイルが壊れています（") + what + " が不足）");
    }
}

// ---------------------------------------------------------------- ango の鍵

std::vector<unsigned char> SodiumKeyOps::wrap_file_key(const SecureBuffer& file_key) {
    const KeyPair& keys = load_();
    std::vector<unsigned char> sealed(crypto_box_SEALBYTES + file_key.size());
    if (crypto_box_seal(sealed.data(), file_key.data(), file_key.size(), keys.pk.data()) != 0) {
        throw CryptoError("ファイル鍵の暗号化に失敗しました");
    }
    return sealed;
}

SecureBuffer SodiumKeyOps::unwrap_file_key(const std::vector<unsigned char>& wrapped) {
    const KeyPair& keys = load_();
    SecureBuffer file_key(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    if (wrapped.size() != kSealedKeyBytes ||
        crypto_box_seal_open(file_key.data(), wrapped.data(), wrapped.size(), keys.pk.data(), keys.sk.data()) != 0) {
        throw CryptoError("復号できません（この鍵で暗号化されたファイルではないか、ファイルが壊れています）");
    }
    return file_key;
}

std::vector<unsigned char> SodiumKeyOps::sign(const std::vector<unsigned char>& message) {
    const KeyPair& keys = load_();
    std::vector<unsigned char> sig(crypto_sign_BYTES);
    crypto_sign_detached(sig.data(), nullptr, message.data(), message.size(), keys.sign_sk.data());
    return sig;
}

void SodiumKeyOps::verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature) {
    const KeyPair& keys = load_();
    if (signature.size() != crypto_sign_BYTES ||
        crypto_sign_verify_detached(signature.data(), message.data(), message.size(), keys.sign_pk.data()) != 0) {
        throw CryptoError("署名が一致しません（あなたの鍵で作られたファイルではないか、改ざんされています）");
    }
}

// ---------------------------------------------------------------- 本体

void encrypt_stream(std::FILE* in, std::FILE* out, KeyOps& keys, PayloadKind kind) {
    SecureBuffer file_key(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    crypto_secretstream_xchacha20poly1305_keygen(file_key.data());

    EncryptedHeader header;
    header.version = keys.format_version();
    header.kind = kind;
    header.wrapped_key = keys.wrap_file_key(file_key);
    if (header.version != kFormatGpg && header.wrapped_key.size() != kSealedKeyBytes) {
        throw CryptoError("ファイル鍵の暗号化に失敗しました");
    }
    if (header.version == kFormatGpg && header.wrapped_key.size() > kMaxGpgBlobBytes) {
        throw CryptoError("GPG で暗号化したファイル鍵が大きすぎます");
    }

    crypto_secretstream_xchacha20poly1305_state state;
    crypto_secretstream_xchacha20poly1305_init_push(&state, header.stream_header.data(), file_key.data());

    const std::vector<unsigned char> head = signed_part(header);
    header.signature = keys.sign(head);
    if (header.version == kFormatGpg) {
        if (header.signature.empty() || header.signature.size() > kMaxGpgBlobBytes) {
            throw CryptoError("GPG の署名の大きさが不正です");
        }
    } else if (header.signature.size() != crypto_sign_BYTES) {
        throw CryptoError("署名に失敗しました");
    }
    write_all(out, head.data(), head.size());
    if (header.version == kFormatGpg) {
        std::vector<unsigned char> len;
        put_u32(len, static_cast<std::uint32_t>(header.signature.size()));
        write_all(out, len.data(), len.size());
    }
    write_all(out, header.signature.data(), header.signature.size());

    std::vector<unsigned char> plain(kChunkSize);
    std::vector<unsigned char> cipher(kChunkSize + crypto_secretstream_xchacha20poly1305_ABYTES);
    bool eof = false;
    while (!eof) {
        const std::size_t len = std::fread(plain.data(), 1, plain.size(), in);
        if (std::ferror(in)) {
            sodium_memzero(plain.data(), plain.size());
            throw std::runtime_error(std::string("読み込みに失敗しました: ") + std::strerror(errno));
        }
        eof = std::feof(in) != 0;
        const unsigned char tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        unsigned long long out_len = 0;
        crypto_secretstream_xchacha20poly1305_push(&state, cipher.data(), &out_len, plain.data(), len,
                                                   nullptr, 0, tag);
        write_all(out, cipher.data(), static_cast<std::size_t>(out_len));
    }
    sodium_memzero(plain.data(), plain.size());
    sodium_memzero(&state, sizeof(state));
}

EncryptedHeader read_header(std::FILE* in) {
    unsigned char magic[sizeof(kMagic)];
    read_exact(in, magic, sizeof(magic), "ヘッダー");
    if (std::memcmp(magic, kMagic, sizeof(kMagic)) != 0) {
        throw CryptoError("Ango で暗号化されたファイルではありません");
    }
    unsigned char version = 0;
    unsigned char kind = 0;
    read_exact(in, &version, 1, "ヘッダー");
    if (version != kFormatUnsigned && version != kFormatSodium && version != kFormatGpg) {
        throw CryptoError("未対応の形式バージョンです: " + std::to_string(version));
    }
    read_exact(in, &kind, 1, "ヘッダー");
    if (kind != static_cast<unsigned char>(PayloadKind::File) &&
        kind != static_cast<unsigned char>(PayloadKind::Tar)) {
        throw CryptoError("不明なデータ種別です");
    }

    EncryptedHeader header;
    header.version = version;
    header.kind = static_cast<PayloadKind>(kind);
    if (version == kFormatGpg) {
        header.wrapped_key = read_blob(in, "ヘッダー");
        read_exact(in, header.stream_header.data(), header.stream_header.size(), "ヘッダー");
        header.signature = read_blob(in, "署名");
    } else {
        header.wrapped_key.resize(kSealedKeyBytes);
        read_exact(in, header.wrapped_key.data(), header.wrapped_key.size(), "ヘッダー");
        read_exact(in, header.stream_header.data(), header.stream_header.size(), "ヘッダー");
        if (header.is_signed()) {
            header.signature.resize(crypto_sign_BYTES);
            read_exact(in, header.signature.data(), header.signature.size(), "署名");
        }
    }
    return header;
}

void verify_header(const EncryptedHeader& header, KeyOps& keys, bool allow_unsigned) {
    if (!keys.supports(header.version)) {
        throw KeyMismatch(mismatch_message(header.version));
    }
    if (!header.is_signed()) {
        if (!allow_unsigned) {
            throw UnsignedFile();
        }
        return;
    }
    keys.verify(signed_part(header), header.signature);
}

void decrypt_stream(std::FILE* in, std::FILE* out, const EncryptedHeader& header, KeyOps& keys) {
    if (!keys.supports(header.version)) {
        throw KeyMismatch(mismatch_message(header.version));
    }
    const SecureBuffer file_key = keys.unwrap_file_key(header.wrapped_key);
    if (file_key.size() != crypto_secretstream_xchacha20poly1305_KEYBYTES) {
        throw CryptoError("復号したファイル鍵の大きさが不正です");
    }

    crypto_secretstream_xchacha20poly1305_state state;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header.stream_header.data(), file_key.data()) != 0) {
        throw CryptoError("暗号化ファイルのヘッダーが壊れています");
    }

    std::vector<unsigned char> cipher(kChunkSize + crypto_secretstream_xchacha20poly1305_ABYTES);
    std::vector<unsigned char> plain(kChunkSize);
    bool finished = false;
    while (!finished) {
        const std::size_t len = std::fread(cipher.data(), 1, cipher.size(), in);
        if (std::ferror(in)) {
            throw std::runtime_error(std::string("読み込みに失敗しました: ") + std::strerror(errno));
        }
        const bool eof = std::feof(in) != 0;
        unsigned long long out_len = 0;
        unsigned char tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(&state, plain.data(), &out_len, &tag, cipher.data(), len,
                                                       nullptr, 0) != 0) {
            sodium_memzero(plain.data(), plain.size());
            throw CryptoError("暗号化ファイルが壊れているか、改ざんされています");
        }
        finished = tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        if (finished && !eof && std::fgetc(in) != EOF) {
            sodium_memzero(plain.data(), plain.size());
            throw CryptoError("暗号化ファイルの末尾に不明なデータがあります");
        }
        if (!finished && eof) {
            sodium_memzero(plain.data(), plain.size());
            throw CryptoError("暗号化ファイルが途中で切れています");
        }
        write_all(out, plain.data(), static_cast<std::size_t>(out_len));
    }
    sodium_memzero(plain.data(), plain.size());
    sodium_memzero(&state, sizeof(state));
}

}  // namespace ang
