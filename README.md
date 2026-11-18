# Kuda

Kuda は、PC の状態を機械的に観測し、通常時と比べて異変を見つけ、LLM に調査を託すための監視ハーネスです。Rust 製の単一バイナリ `kuda` で、常駐しません。OS のスケジューラ（Windows のタスクスケジューラ、Linux の systemd user timer）が 5 分ごとに `kuda check` を起動し、1 回分の監視が終わると終了します。

異変の検知（probe の結果が条件式に合うか）は LLM を使わずに行います。LLM を呼ぶのは、条件を満たして発火したあとの調査だけです。

## 目的と非目標

Kuda は、ネットワークの疎通や、普段いないプロセスの出現といった「いつもと違う」状態を見つけ、原因の調査を LLM に引き継ぎます。次のことは目標にしていません。

- EDR やアンチウイルスの代替にはなりません。マルウェア検知ではなく、未知のものが現れたことの検知です
- 5 分間隔のポーリングなので、短時間で終わるプロセスや瞬断は見逃します
- 管理者権限を要求しません。ユーザー権限で見えないもの（保護プロセスのパスなど）は扱えません
- 隠蔽には対抗しません。同じユーザー権限で Kuda の DB や設定を書き換えられると防げません
- LLM の調査結果を自動で反映しません。既知の集合への追加などは、利用者が操作して行います

## サブコマンド

| コマンド | 内容 |
| --- | --- |
| `kuda check` | 1 回分の監視を実行する。スケジューラが起動するのはこれです（`--force` で interval を無視） |
| `kuda snapshot` | スナップショットを取り、成功した collector の分を `last_known_good` として保存する |
| `kuda diagnose --watch <名前>` | 事件ディレクトリを作り、LLM に調査させる（`--dry-run` で事件ディレクトリだけ作る） |
| `kuda status` | watch ごとのサンプル数、ベースライン、スナップショット、クールダウンを表示する |
| `kuda check-config` | 設定ファイルと、それが参照するもの（プロンプト、バックエンドのコマンド）を検証する |
| `kuda check-backends` | LLM バックエンドが使える状態かを表示する |

全サブコマンドで `--verbose` が使えます（debug ログを標準エラーにも出します）。Windows には、窓を出さないスケジューラ用の GUI サブシステム版 `kudaw.exe` もあります。

## クイックスタート

ビルドは Nix flake で行います（Rust ツールチェーンは個別に要りません）。Windows 向けも WSL 上の Nix でクロスビルドします。手順の詳細は [docs/handoff.md](docs/handoff.md) を見てください。

```bash
nix build .#kuda            # Linux。Windows 向けは nix build .#kuda-windows
```

設定ファイルは `config.example.toml` をコピーして編集します（置き場所は handoff.md の「配置とディレクトリ構成」）。そのあと、次の順で確かめます。

```bash
kuda check-config           # 設定と参照先の検証
kuda check --verbose        # 1 回分の監視。probe の結果とトリガー判定を見る
kuda status                 # 記録の状態を見る
```

スケジューラへの登録、LLM バックエンドの準備、運用とトラブルシューティングは [docs/handoff.md](docs/handoff.md) にあります。

## ドキュメント

- [docs/handoff.md](docs/handoff.md): ビルド、配置、設定、スケジューラ登録、運用の手順書
- [docs/architecture.md](docs/architecture.md): コードを変える人向けの設計。処理の流れ、モジュール構成、データモデル、用語
- [docs/process-watch-plan.md](docs/process-watch-plan.md): プロセス監視（`kind = "process"`）の実装指示書
- [docs/kuda_naming_handoff.md](docs/kuda_naming_handoff.md): 名前の由来と、LLM に与える権限を絞る方針
