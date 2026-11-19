# Tor Watch Public OSINT

公開・明示登録した .onion URL を対象に、ページ変更とキーワードを監視する防御目的のOSINTツールです。

## Features
- Tor SOCKS5経由で登録済みURLのみ取得
- ページ本文のSHA-256比較
- 新規/変更ページ検出
- キーワード・監視資産のマッチング
- リスクスコア（0-100）
- 変更差分の抽出
- SQLite履歴
- Slack通知
- Streamlitダッシュボード
- GitHub Actionsによる6時間ごとの実行
- Torなしで動作確認できるdemo mode

## Safety
このプロジェクトは、利用者が明示的に登録した公開ページの監視に限定します。Tor通信の傍受、認証回避、アクセス制御回避、資格情報の取得、未登録サイトの大量探索は実装しません。

## Setup
1. `config/watchlist.txt` に監視対象URLを1行ずつ登録。
2. `config/assets.yml` に自分が監視したいドメイン、メールアドレス、組織名などを登録。
3. `config/keywords.txt` に高リスク語を登録。
4. `pip install -r requirements.txt`。
5. Torを起動し、SOCKS5を `127.0.0.1:9050` に公開。
6. `python -m torwatch.cli --run`。
7. Dashboard: `streamlit run app.py`

GitHub ActionsではリポジトリSecret `SLACK_WEBHOOK_URL` を設定すると通知できます。

## Demo
`python -m torwatch.cli --demo` でTor接続なしのサンプルデータを生成できます.


## Web dashboard
The `web/` directory is a static dashboard designed for GitHub Pages. GitHub Actions runs the monitor, exports `data/history.db` to `web/data.json`, and publishes the dashboard. Enable GitHub Pages with the Actions deployment workflow as the source.


## Public company threat-intelligence monitoring

In addition to the explicitly registered Tor pages, the monitor checks configured public HTTPS RSS/Atom feeds in `config/sources.yml`.
It matches article titles and summaries against the names/domains in `config/assets.yml`, then requires incident-related language before storing an alert.

- Public RSS/Atom metadata only; it does not download linked leak files or access restricted systems.
- New matching alerts are stored in SQLite (`data/history.db`) and exported to the GitHub Pages dashboard.
- Slack notifications use the `SLACK_WEBHOOK_URL` repository secret.
- Alert status is explicitly marked as public reporting / not independently confirmed by the affected company.
- Feed errors are isolated per source. Only HTTPS feed URLs are accepted.

Run locally with `python -m torwatch.cli --run` after installing dependencies. Run tests with `python -m unittest discover -s tests`.
