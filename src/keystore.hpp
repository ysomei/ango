// 鍵ファイルの読み書きと、設定（秘密鍵の場所）の管理
// 鍵そのものは PC に保存しない。秘密鍵ファイル（USB 上）だけで暗号化・署名・復号を行う。
#pragma once

#include "crypto.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace ang {

namespace fs = std::filesystem;

constexpr const char* kSecretKeyFileName = "ang_secret.key";

class WrongPassphrase : public std::runtime_error {
public:
    WrongPassphrase() : std::runtime_error("パスフレーズが違います") {}
};

// 小さなファイルの読み書き（鍵・キャッシュ用）
void put_u64(std::vector<unsigned char>& buf, std::uint64_t value);
std::uint64_t get_u64(const unsigned char* p);
// 新規作成（既にあれば失敗）
void write_new_file(const fs::path& path, const std::vector<unsigned char>& data, unsigned int mode);
// 一時ファイル経由で置き換える
void replace_file(const fs::path& path, const std::vector<unsigned char>& data, unsigned int mode);
// ちょうど expected_size バイトのファイルを読む（大きさが違えば例外）
std::vector<unsigned char> read_small_file(const fs::path& path, std::size_t expected_size);

// 秘密鍵ファイル（パスフレーズで暗号化）
void write_secret_key_file(const fs::path& path, const KeyPair& keys, const std::string& passphrase);
KeyPair read_secret_key_file(const fs::path& path, const std::string& passphrase);

// 設定フォルダ（macOS: ~/Library/Application Support/ang, その他: ~/.config/ang）
fs::path config_dir();

// 秘密鍵の「場所」だけを保存する（鍵そのものは保存しない）
std::optional<fs::path> load_secret_key_location();
void save_secret_key_location(const fs::path& path);
void forget_secret_key_location();

// ~ の展開、ターミナルへのドラッグ&ドロップで付く引用符・エスケープの除去
fs::path normalize_user_path(const std::string& input);

}  // namespace ang
