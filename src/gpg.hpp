// GPG の鍵を使う暗号化・署名（gpg コマンドを呼び出す）
//
// ファイル本文は ango と同じ方式（XChaCha20-Poly1305）で暗号化し、
// ファイル鍵の暗号化とヘッダーへの署名だけを gpg に任せる。
// GPG の鍵は USB 上の GNUPGHOME に置き、その中に設定ファイル ang_gpg.key（使う鍵のフィンガープリント）を置く。
#pragma once

#include "crypto.hpp"
#include "process.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace ang {

namespace fs = std::filesystem;

constexpr const char* kGpgKeyFileName = "ang_gpg.key";

struct GpgKeyRef {
    fs::path homedir;         // GNUPGHOME（ang_gpg.key のあるフォルダ）
    std::string fingerprint;  // 主鍵のフィンガープリント（大文字 16 進）
};

struct GpgKeyInfo {
    std::string fingerprint;
    std::string user_id;
};

// ang_gpg.key かどうか（先頭行で判定する）
bool is_gpg_key_file(const fs::path& path);
GpgKeyRef read_gpg_key_file(const fs::path& path);
void write_gpg_key_file(const fs::path& path, const std::string& fingerprint);

// GNUPGHOME らしいフォルダか（鍵の保管ファイルがある）
bool looks_like_gpg_homedir(const fs::path& dir);

// 鍵ファイル（gpg --export / --export-secret-keys で書き出したもの）を homedir に取り込み、
// 取り込んだ鍵の主鍵フィンガープリントを返す。homedir が無ければ作る
std::vector<std::string> import_gpg_keys(const fs::path& homedir, const std::vector<fs::path>& files);

// 秘密鍵を含む鍵ファイル（ASCII 形式）か
bool is_secret_key_file(const fs::path& path);

// homedir にある、暗号化と署名の両方に使える秘密鍵を探す（query が空ならすべて）
std::vector<GpgKeyInfo> find_gpg_secret_keys(const fs::path& homedir, const std::string& query);

// gpg-agent・scdaemon など、homedir 用の gpg のプロセスをすべて止める（パスフレーズの記憶も消える）。
// homedir が無ければ何もしない
void gpg_forget_passphrase(const fs::path& homedir);

class GpgKeyOps : public KeyOps {
public:
    explicit GpgKeyOps(GpgKeyRef ref);
    ~GpgKeyOps() override;
    GpgKeyOps(const GpgKeyOps&) = delete;
    GpgKeyOps& operator=(const GpgKeyOps&) = delete;

    unsigned char format_version() const override { return kFormatGpg; }
    bool supports(unsigned char version) const override { return version == kFormatGpg; }
    std::vector<unsigned char> wrap_file_key(const SecureBuffer& file_key) override;
    SecureBuffer unwrap_file_key(const std::vector<unsigned char>& wrapped) override;
    std::vector<unsigned char> sign(const std::vector<unsigned char>& message) override;
    void verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature) override;

private:
    PipedResult run(const std::vector<std::string>& args, const std::string& input, const std::string* fd3);
    // 秘密鍵を使う処理。gpg-agent が覚えていなければパスフレーズを尋ねる
    PipedResult run_with_secret(const std::vector<std::string>& args, const std::string& input, const char* what);

    GpgKeyRef ref_;
    std::optional<std::string> passphrase_;  // この実行中に入力されたもの（gpg-agent が覚えない設定のとき用）
};

}  // namespace ang
