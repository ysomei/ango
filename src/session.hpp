// 解錠キャッシュ: パスフレーズを毎回入力しなくて済むようにする
//
// パスフレーズで解錠した鍵を、使い捨ての鍵 K で暗号化して USB 上（秘密鍵の隣）に置き、
// K は PC 側に置く。両方が揃ったときだけ鍵を取り出せる。
//   - USB を抜く → PC 側の K だけでは何も開けない
//   - USB だけ盗まれる → K が無いので開けない
//   - 最後に使ってから kSessionTimeout を過ぎる / PC を再起動する → 無効
// パスフレーズを入力するたびに新しい K を作る。
#pragma once

#include "crypto.hpp"

#include <chrono>
#include <filesystem>
#include <optional>

namespace ang {

constexpr std::chrono::minutes kSessionTimeout{30};

// 有効なキャッシュがあれば鍵を取り出し、有効期限を延長する。無効なら残骸を消して nullopt
std::optional<KeyPair> load_session(const std::filesystem::path& secret_key_path);

// 新しい K でキャッシュを作る（失敗しても致命的ではないので例外は投げず、警告だけ出す）
void create_session(const std::filesystem::path& secret_key_path, const KeyPair& keys);

// キャッシュを消す（USB 側は挿さっていれば消す）
void clear_session(const std::optional<std::filesystem::path>& secret_key_path);

}  // namespace ang
