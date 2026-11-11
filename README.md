# Atode

PCとスマホから記事・ワード・リンクをすぐ保存できるメモアプリ（PWA）。

- 保存先: 端末内 + Dropbox（アプリフォルダの `atode.json` / `atode.md`）
- `atode.md` は鍵付きクリップを除いた一覧。Claude の Dropbox コネクタから読める
- 鍵付きクリップは合言葉（PBKDF2 + AES-GCM）で端末内で暗号化してから保存
- 追加方法: 入力欄 / Android の共有メニュー / PC のブックマークレット / iPhone のショートカット
- Google Keep の Takeout ZIP を読み込み可能（パスワードらしきメモは自動で鍵付きに）
