// 暗号処理（鍵ペア生成・ストリーム暗号化/復号）
#pragma once

#include <sodium.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace ang {

// sodium_malloc で確保する保護付きメモリ（解放時にゼロクリアされる）
class SecureBuffer {
public:
    explicit SecureBuffer(std::size_t size);
    ~SecureBuffer();
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    unsigned char* data() { return data_; }
    const unsigned char* data() const { return data_; }
    std::size_t size() const { return size_; }

private:
    unsigned char* data_ = nullptr;
    std::size_t size_ = 0;
};

using PublicKey = std::array<unsigned char, crypto_box_PUBLICKEYBYTES>;
using SignPublicKey = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>;

struct KeyPair {
    PublicKey pk{};
    SecureBuffer sk{crypto_box_SECRETKEYBYTES};
    // 署名鍵は sk から導出する（ファイルには保存しない）
    SignPublicKey sign_pk{};
    SecureBuffer sign_sk{crypto_sign_SECRETKEYBYTES};
};

// 暗号化された中身の種類
enum class PayloadKind : std::uint8_t {
    File = 0,  // 単一ファイル (.ang)
    Tar = 1,   // フォルダを tar にまとめたもの (.tar.ang)
};

// .ang の形式バージョン
constexpr unsigned char kFormatUnsigned = 1;  // 署名なし（旧形式）
constexpr unsigned char kFormatSodium = 2;    // ango の鍵 (ang_secret.key) で暗号化・署名
constexpr unsigned char kFormatGpg = 3;       // GPG の鍵で暗号化・署名

// .ang ファイルの先頭部分
struct EncryptedHeader {
    unsigned char version = 0;
    PayloadKind kind = PayloadKind::File;
    std::vector<unsigned char> wrapped_key;  // 暗号化されたファイル鍵
    std::array<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES> stream_header{};
    std::vector<unsigned char> signature;  // version 2 以降

    bool is_signed() const;
};

class UnsignedFile : public std::runtime_error {
public:
    UnsignedFile()
        : std::runtime_error("署名のない旧形式のファイルです（作成者を確認できません）。"
                             "自分で作ったファイルであれば --allow-unsigned を付けて復号できます") {}
};

class CryptoError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// 指定されている鍵とは別の種類の鍵で暗号化されたファイル
class KeyMismatch : public CryptoError {
public:
    using CryptoError::CryptoError;
};

void init_crypto();

KeyPair generate_keypair();

// keys.sk から署名鍵 (sign_pk, sign_sk) を導出して設定する
void derive_signing_keys(KeyPair& keys);

// 鍵の種類ごとの処理（ファイル鍵の暗号化と、ヘッダーへの署名）
class KeyOps {
public:
    virtual ~KeyOps() = default;
    // この鍵で作る .ang の形式バージョン
    virtual unsigned char format_version() const = 0;
    // header.version のファイルをこの鍵で扱えるか
    virtual bool supports(unsigned char version) const = 0;
    virtual std::vector<unsigned char> wrap_file_key(const SecureBuffer& file_key) = 0;
    // 復号できなければ CryptoError
    virtual SecureBuffer unwrap_file_key(const std::vector<unsigned char>& wrapped) = 0;
    virtual std::vector<unsigned char> sign(const std::vector<unsigned char>& message) = 0;
    // 署名が合わなければ CryptoError
    virtual void verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature) = 0;
};

// ango の鍵 (X25519 sealed box + Ed25519)。鍵ペアは最初に必要になったときに load で読み込む
class SodiumKeyOps : public KeyOps {
public:
    explicit SodiumKeyOps(std::function<const KeyPair&()> load) : load_(std::move(load)) {}
    unsigned char format_version() const override { return kFormatSodium; }
    bool supports(unsigned char version) const override {
        return version == kFormatSodium || version == kFormatUnsigned;
    }
    std::vector<unsigned char> wrap_file_key(const SecureBuffer& file_key) override;
    SecureBuffer unwrap_file_key(const std::vector<unsigned char>& wrapped) override;
    std::vector<unsigned char> sign(const std::vector<unsigned char>& message) override;
    void verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature) override;

private:
    std::function<const KeyPair&()> load_;
};

// in の内容をファイル鍵で暗号化し、ファイル鍵とヘッダーへの署名を keys で作って out に書き出す
void encrypt_stream(std::FILE* in, std::FILE* out, KeyOps& keys, PayloadKind kind);

// .ang のヘッダーを読む（形式が不正なら CryptoError）
EncryptedHeader read_header(std::FILE* in);

// ヘッダーの署名を確かめる（署名が合わなければ CryptoError、署名なしで allow_unsigned でなければ UnsignedFile、
// 鍵の種類が違えば KeyMismatch）
void verify_header(const EncryptedHeader& header, KeyOps& keys, bool allow_unsigned);

// read_header 後の残りを復号して out に書き出す（改ざん・破損・鍵違いは CryptoError）
// verify_header を通したヘッダーで呼ぶこと
void decrypt_stream(std::FILE* in, std::FILE* out, const EncryptedHeader& header, KeyOps& keys);

// I/O ヘルパー
void write_all(std::FILE* out, const void* data, std::size_t size);
void read_exact(std::FILE* in, void* data, std::size_t size, const char* what);

}  // namespace ang
