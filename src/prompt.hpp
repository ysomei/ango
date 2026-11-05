// ユーザーへの問い合わせ
// ターミナルから実行された場合は端末で、Finder 連携など端末がない場合は macOS のダイアログで尋ねる。
#pragma once

#include <optional>
#include <stdexcept>
#include <string>

namespace ang {

class Cancelled : public std::runtime_error {
public:
    Cancelled() : std::runtime_error("キャンセルしました") {}
};

// 端末がない（ダイアログで尋ねる）なら true
bool gui_mode();

// 1 行入力。キャンセル/EOF なら nullopt
std::optional<std::string> ask_line(const std::string& message);

// パスフレーズ入力（エコーなし）。キャンセル/EOF なら nullopt
std::optional<std::string> ask_passphrase(const std::string& message);

// ファイルの場所を尋ねる（GUI ではファイル選択ダイアログ）。キャンセルなら nullopt
std::optional<std::string> ask_file_location(const std::string& message);

// GUI モードならエラーダイアログを表示する
void show_error(const std::string& message);

}  // namespace ang
