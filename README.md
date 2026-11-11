# Atode

PCとスマホから記事・ワード・リンクをすぐ保存できるメモアプリ（PWA）。

- 保存先: 端末内 + Dropbox（アプリフォルダの `atode.json` / `atode.md`）
- `atode.md` は鍵付きクリップを除いた一覧。Claude の Dropbox コネクタから読める
- 鍵付きクリップは合言葉（PBKDF2 + AES-GCM）で端末内で暗号化してから保存
- 追加方法: 入力欄 / Android の共有メニュー / PC のブックマークレット / iPhone のショートカット
- Google Keep の Takeout ZIP を読み込み可能（パスワードらしきメモは自動で鍵付きに）
- リンクのプレビュー（タイトル・画像）は microlink.io から取得し、端末内にキャッシュ（鍵付きクリップは対象外）

## スマホ

- Android（Chrome）: メニューの「アプリをインストール」（または設定の「アプリとしてインストール」）でホーム画面に追加すると、共有メニューに Atode が出る
- iPhone: Safari の共有 →「ホーム画面に追加」。PWA は共有先に出られないので、ショートカットで Dropbox の `/アプリ/Atode/atode-inbox.txt` に1行ずつ追記し、Atode が次の同期で取り込んで消す（行は URL エンコード可）
