#!/bin/bash
# Finder から使うための小さなアプリ（AppleScript ドロップレット）を作成する
#
#   Ango 暗号化.app  … ファイル/フォルダをドロップ、または「このアプリケーションで開く」で暗号化
#   Ango 復号.app    … .ang ファイルのダブルクリックで復号して開く
#
# 使い方: scripts/install_macos_apps.sh [ango のパス]
#   作成先は ~/Applications（環境変数 ANG_APP_DIR で変更可）
set -euo pipefail

ANG_BIN="${1:-$(command -v ango || true)}"
if [[ -z "$ANG_BIN" || ! -x "$ANG_BIN" ]]; then
    echo "ango の実行ファイルが見つかりません。パスを引数で指定してください。" >&2
    echo "例: $0 /usr/local/bin/ango" >&2
    exit 1
fi
ANG_BIN="$(cd "$(dirname "$ANG_BIN")" && pwd)/$(basename "$ANG_BIN")"
DEST="${ANG_APP_DIR:-$HOME/Applications}"
mkdir -p "$DEST"

LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister

# 旧名（Ang）で作ったアプリが残っていれば取り除く（バンドルIDが同じで紛らわしいため）
for old in "Ang 暗号化" "Ang 復号"; do
    if [[ -d "$DEST/$old.app" ]]; then
        if [[ -z "${ANG_NO_REGISTER:-}" ]]; then
            "$LSREGISTER" -u "$DEST/$old.app" || true
        fi
        rm -rf "$DEST/$old.app"
        echo "旧アプリを削除しました: $DEST/$old.app"
    fi
done

# $1: アプリ名, $2: ango に渡すサブコマンドとオプション
make_app() {
    local app="$DEST/$1.app"
    rm -rf "$app"
    # エラー表示は ango 自身がダイアログで行うので、ここでは握りつぶす
    osacompile -o "$app" - <<EOF
on open theItems
	set cmd to quoted form of "$ANG_BIN" & " $2"
	repeat with f in theItems
		set cmd to cmd & " " & quoted form of POSIX path of f
	end repeat
	try
		do shell script cmd
	end try
end open

on run
	display dialog "ファイルやフォルダをこのアプリにドロップしてください。" buttons {"OK"} default button 1 with title "Ango"
end run
EOF
}

# $1: アプリ名, $2: バンドルID, $3: CFBundleDocumentTypes(JSON), $4: UTExportedTypeDeclarations(JSON, 省略可)
configure_app() {
    local app="$DEST/$1.app"
    local plist="$app/Contents/Info.plist"
    plutil -replace CFBundleIdentifier -string "$2" "$plist"
    plutil -replace CFBundleDocumentTypes -json "$3" "$plist"
    if [[ -n "${4:-}" ]]; then
        plutil -replace UTExportedTypeDeclarations -json "$4" "$plist"
    fi
    # Info.plist を変更したので署名し直す（アドホック署名）
    codesign --force --sign - "$app" >/dev/null 2>&1
    if [[ -z "${ANG_NO_REGISTER:-}" ]]; then
        "$LSREGISTER" -f "$app"
    fi
}

make_app "Ango 暗号化" "encrypt"
configure_app "Ango 暗号化" "local.ang.encrypt" \
    '[{"CFBundleTypeName":"Any Item","CFBundleTypeRole":"Viewer","LSHandlerRank":"Alternate","LSItemContentTypes":["public.item"]}]'

make_app "Ango 復号" "decrypt --open"
configure_app "Ango 復号" "local.ang.decrypt" \
    '[{"CFBundleTypeName":"Ango Encrypted File","CFBundleTypeRole":"Editor","LSHandlerRank":"Owner","LSItemContentTypes":["local.ang.encrypted"]}]' \
    '[{"UTTypeIdentifier":"local.ang.encrypted","UTTypeDescription":"Ango Encrypted File","UTTypeConformsTo":["public.data"],"UTTypeTagSpecification":{"public.filename-extension":["ang"]}}]'

echo "作成しました:"
echo "  $DEST/Ango 暗号化.app"
echo "  $DEST/Ango 復号.app"
echo
echo ".ang をダブルクリックしても開かない場合は、.ang ファイルを選んで「情報を見る」→"
echo "「このアプリケーションで開く」で「Ango 復号」を選び、「すべてを変更」を押してください。"
