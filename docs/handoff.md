# Kuda（PC監視LLMハーネス）ローカル実行手順書


## 概要

ハーネス Kuda（Rust製の単一バイナリ `kuda`）を常駐させず、OSのスケジューラから5分ごとに `kuda check` として起動します。アイドル時のメモリ消費は実質ゼロです。

1回の起動で行うことは次のとおりです。

1. 設定ファイルを読み、各 watch の probe（TCP/ICMP/DNS など）を実行する
2. 結果をSQLiteに記録し、統計ベースラインを更新する
3. 正常時で、前回の取得から `snapshot_interval` 以上経っていれば、スナップショットを取って `last_known_good` として保存する
4. トリガー条件（連続回数・クールダウン込み）を判定する
5. 発火した場合は、事件ディレクトリ（現在のスナップショット、正常時との差分、メトリクス）を生成し、調査プロセスを切り離して起動したうえで自身は即終了する

&#91;embedded content: check の1回分の流れ · 判定2箇所\]

正常時はスナップショットの更新だけで終わり、異常がトリガー条件を満たしたときだけ調査プロセスが残ります。

本書は、設計どおりに実装した `kuda` を開発機1台でビルドし、配置・設定・スケジューラ登録・動作確認するまでの手順です。コマンド名やサブコマンドは設計時点の想定で、実装に合わせて読み替えてください。

## 前提条件

ビルドはNix flakeで行い、Rustツールチェーンは個別に入れません。Windows向けのバイナリもWSL上のNixでクロスビルドします。実行には少なくとも1つのLLMバックエンドが必要です。管理者権限はスケジューラ登録時にも不要です（ユーザー権限で動かします）。

| 項目 | Windows 11 | GNU/Linux |
| --- | --- | --- |
| ビルド環境 | WSL2 上の Linux ディストリビューション（または NixOS-WSL）に Nix を導入。Windows 側に Rust や MSVC は不要 | Nix（flakes 有効） |
| Nix の設定 | `nix.conf` に `experimental-features = nix-command flakes` | 同左 |
| ビルドターゲット | `x86_64-pc-windows-gnu`（mingw-w64） | ネイティブ |
| SQLite | 不要（`rusqlite` の bundled 機能で同梱） | 同左 |
| traceroute | `tracert`（標準搭載） | `traceroute` パッケージ（無ければ `sudo apt install traceroute` など） |
| スケジューラ | タスクスケジューラ（標準） | systemd（user インスタンス） |
| LLM（いずれか1つ以上） | Claude Code / Codex CLI / Ollama か llama.cpp | 同左 |

LLM CLIは、スケジューラがタスクを実行するのと**同じユーザー**でログイン済みにしておきます。別ユーザーで実行すると認証情報が見つかりません。

## ビルド

Nix flakeでリリースビルドのバイナリを作ります。Windows向けもWSL上のNixからクロスビルドします。Windowsでは、タスク起動のたびにコンソール窓が出ないよう、スケジューラ用のGUIサブシステム版 `kudaw.exe` も作ります。

### プロジェクト構成（想定）

```
kuda/
  flake.nix
  flake.lock
  Cargo.toml
  Cargo.lock
  src/
    lib.rs             # CLI（check / snapshot / diagnose / status / check-config / check-backends）
    main.rs            # kuda の入口
    bin/kudaw.rs       # kudaw の入口（Windows では GUI サブシステム）
    commands.rs        # 各サブコマンドの本体
    config.rs          # config.toml の読み込みと検証
    paths.rs           # OS別のディレクトリ解決（Linux は XDG）
    probe/             # tcp, icmp, dns, http, command
    store.rs           # SQLite: メトリクス・集計・スナップショット・状態
    baseline.rs        # 時間帯別 p50/p95、last_known_good 管理
    collector/         # adapters, routes, dns_config, traceroute
    trigger.rs         # 条件式・連続回数・クールダウン
    incident.rs        # 事件ディレクトリ生成、diff 生成
    diagnosis/         # claude_code, codex, local
    lock.rs            # 多重起動防止
    detach.rs          # 調査プロセスの切り離し起動
    process.rs         # 外部コマンドの起動（タイムアウト、窓を出さない）
    logging.rs         # 日付ローテーションするファイルログ
  prompts/
    network.md
  config.example.toml
  tests/
    e2e.rs             # 実バイナリでの通しテスト
```

主な依存クレートは `rusqlite`（bundled）、`serde` と `serde_json`、`toml`、`clap`、`anyhow`、`chrono`、`log`、`fd-lock`、`ureq`（ローカルLLMへのHTTP）です。Windowsでは `windows`（`GetAdaptersAddresses`、`GetIpForwardTable2`、`IcmpSendEcho2`）を、Linuxでは `ip -j` の呼び出しと `socket2`（非特権の ping ソケット）を使います。メモリと起動時間を抑えるため、tokio などの非同期ランタイムは入れず同期実装にします。

### Windowsでコンソール窓を出さない

Windows向けには2つのバイナリを作ります。中身は同じで、サブシステムだけが違います（Python の `python.exe` と `pythonw.exe` の関係です）。

| バイナリ | サブシステム | 用途 |
| --- | --- | --- |
| `kuda.exe` | コンソール | 手動の実行。PowerShell などから普通に使える |
| `kudaw.exe` | GUI | タスクスケジューラからの起動。窓を出さない |

`kudaw` は `src/bin/kudaw.rs` の先頭で、次の属性によりGUIサブシステムにしています。

```rust
#![cfg_attr(windows, windows_subsystem = "windows")]
```

GUIサブシステムの exe は標準出力がコンソールに繋がらず、PowerShell は終了も待ちません。手元で `kudaw.exe` を実行すると、何も表示されずに動いていないように見えます。手動の確認には `kuda.exe` を使ってください。`kudaw.exe` の動作はログファイルで確認します（配置の節を参照）。

### flake.nix

flake の出力は次の3つです。Windows向けは `pkgsCross.mingwW64` によるクロスビルドで、ターゲットは MSVC ではなく `x86_64-pc-windows-gnu` になります（`windows` クレートや `windows_subsystem` 属性はそのまま使えます）。

| 出力 | 中身 |
| --- | --- |
| `packages.<system>.default`（`kuda`） | Linux ネイティブのバイナリ。`share/kuda/` に設定例とプロンプトを同梱 |
| `packages.<system>.kuda-windows` | Windows 11 向けの `kuda.exe` と `kudaw.exe`。同じく設定例とプロンプトを同梱 |
| `devShells.<system>.default` | cargo、rustc、clippy、rust-analyzer、sqlite、traceroute 入りの開発シェル |

```nix
{
  description = "Kuda - PC monitoring harness with LLM-driven investigation";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        lib = pkgs.lib;
        cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

        # ビルドに必要なファイルだけをストアに入れる（target/ などを除外）
        src = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./Cargo.toml
            ./Cargo.lock
            ./src
            ./prompts
            ./config.example.toml
          ];
        };

        # p = ビルド先プラットフォームの package set（ネイティブ or pkgsCross.*）
        mkKuda = p:
          let isWindows = p.stdenv.hostPlatform.isWindows;
          in p.rustPlatform.buildRustPackage {
            pname = "kuda";
            version = cargoToml.package.version;
            inherit src;
            cargoLock.lockFile = ./Cargo.lock;

            # mingw の std が要求するスレッドライブラリ
            buildInputs = lib.optionals isWindows [ p.windows.pthreads ];

            # クロスビルドしたテストはビルド機で実行できないためスキップ
            doCheck = !isWindows;

            # 設定例とプロンプトを $out/share/kuda に同梱する
            postInstall = ''
              install -Dm644 config.example.toml $out/share/kuda/config.example.toml
              mkdir -p $out/share/kuda/prompts
              cp -r prompts/. $out/share/kuda/prompts/
            '';

            meta = {
              description = "PC monitoring harness with LLM-driven investigation";
              mainProgram = "kuda";
              platforms = lib.platforms.linux ++ lib.platforms.windows;
            };
          };
      in
      {
        packages = {
          default = mkKuda pkgs;
          kuda = mkKuda pkgs;
          # Windows 11 向け (x86_64-pc-windows-gnu)。WSL 上でクロスビルドする
          kuda-windows = mkKuda pkgs.pkgsCross.mingwW64;
        };

        apps.default = flake-utils.lib.mkApp { drv = self.packages.${system}.default; };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
            sqlite        # DB の中身確認用（ビルドには不要: rusqlite bundled）
            traceroute
          ];
        };

        formatter = pkgs.nixfmt-rfc-style;
      });
}
```

flake は **git で追跡されているファイルしか見えません**。`flake.nix`、`Cargo.lock`、`prompts/` などは、ビルド前に少なくとも `git add` しておいてください。`flake.lock` もコミットして、nixpkgs のバージョンを固定します。

### ビルド手順（Linux）

1. リポジトリのルートでビルドする。初回は `flake.lock` が生成されます。

```bash
nix build .#kuda
ls -lh result/bin/kuda   # サイズの目安は数MB
```

2. 開発中は devShell で cargo を直接使う。

```bash
nix develop
cargo build            # デバッグビルド（コンソール出力あり）
cargo clippy
```

### ビルド手順（Windows: WSL 上でクロスビルド）

1. WSL2 のディストリビューションに Nix を入れ、flakes を有効にする（NixOS-WSL なら設定済みにできます）。
2. リポジトリを WSL 側のファイルシステム（例: `~/src/kuda`）に置く。`/mnt/c` 配下はファイルアクセスが遅く、ビルドが大幅に遅くなります。
3. Windows 向けパッケージをビルドする。

```bash
nix build .#kuda-windows
ls -lh result/bin/kuda.exe
```

4. 依存DLLを確認する。Windows 標準のDLL（`KERNEL32.dll`、`WS2_32.dll`、`IPHLPAPI.DLL` など）以外が出てきた場合（mingw のランタイムDLLなど）は、`kuda.exe` と同じフォルダに同梱するか、静的リンクに切り替えてください。

```bash
nix shell nixpkgs#pkgsCross.mingwW64.buildPackages.binutils \
  -c x86_64-w64-mingw32-objdump -p result/bin/kuda.exe | grep "DLL Name"
```

5. Windows 側への配置は、次の「配置とディレクトリ構成」で WSL から行います。

サイズをさらに削る場合は、`Cargo.toml` に次を追加します。

```toml
[profile.release]
opt-level = "s"
lto = true
strip = true
panic = "abort"
```

## 配置とディレクトリ構成

設定・データ・ログはユーザー領域に置きます。Linuxでは [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir/latest/) に従います。環境変数 `KUDA_HOME` を設定した場合は、OSを問わずその下にすべてをまとめます（Windowsと同じ構成）。

| 用途 | Windows | Linux（XDG。括弧内は変数が未設定・空のときの既定値） |
| --- | --- | --- |
| バイナリ | `%LOCALAPPDATA%\kuda\bin\kuda.exe`、`kudaw.exe` | Nixプロファイル（`~/.nix-profile/bin/kuda`） |
| 設定・プロンプト | `%LOCALAPPDATA%\kuda\config.toml`、`prompts\` | `$XDG_CONFIG_HOME/kuda/config.toml`、`prompts/`（`~/.config`） |
| メトリクスDB（SQLite） | `%LOCALAPPDATA%\kuda\data\kuda.db` | `$XDG_STATE_HOME/kuda/kuda.db`（`~/.local/state`） |
| 事件ディレクトリ | `%LOCALAPPDATA%\kuda\incidents\` | `$XDG_STATE_HOME/kuda/incidents/` |
| ログ | `%LOCALAPPDATA%\kuda\logs\` | `$XDG_STATE_HOME/kuda/logs/` |
| レポート | `%LOCALAPPDATA%\kuda\reports\` | `$XDG_DATA_HOME/kuda/reports/`（`~/.local/share`） |
| ロックファイル | `%LOCALAPPDATA%\kuda\data\kuda.lock` | `$XDG_RUNTIME_DIR/kuda/kuda.lock` |

Linux側の振り分けの考え方は次のとおりです。

- **レポート**は、人が後から読み返す成果物なので `XDG_DATA_HOME` に置きます。
- **メトリクスDB・事件ディレクトリ・ログ**は、再起動をまたいで使うものの、ユーザーにとって重要度や可搬性が低いので `XDG_STATE_HOME` に置きます。仕様ではログや履歴、再開用の状態がここに入るとされています。
- **ロックファイル**は同期用の小さなファイルなので `XDG_RUNTIME_DIR` に置きます。ログアウトや再起動で消えても問題ありません。

`paths.rs` での実装ルールは次のとおりです（仕様の要求そのもの）。

1. 変数が未設定または空なら、上表の既定値を使う。
2. 値が**相対パス**なら無効として無視し、既定値を使う。
3. `XDG_RUNTIME_DIR` が無い場合（cron から起動したときなど）は、`$XDG_STATE_HOME/kuda/run/` を代わりに使い、警告をログに出す。
4. 書き込み先のディレクトリが無ければ、パーミッション `0700` で作成する。既にあるディレクトリのパーミッションは変えない。

バイナリの置き場所について、仕様は `~/.local/bin` を「置いてもよい」場所として挙げているだけです。本手順では Nix プロファイルに管理を任せます。

### Windows

WSL 上でビルドした成果物を、WSL から Windows 側の `%LOCALAPPDATA%` にコピーします。

```bash
# Windows の %LOCALAPPDATA% を WSL のパスに変換
WINLOCAL=$(wslpath "$(cmd.exe /c 'echo %LOCALAPPDATA%' 2>/dev/null | tr -d '\r')")
DEST="$WINLOCAL/kuda"

nix build .#kuda-windows
install -Dm755 result/bin/kuda.exe "$DEST/bin/kuda.exe"
install -Dm755 result/bin/kudaw.exe "$DEST/bin/kudaw.exe"
# 初回のみ: 設定例とプロンプトをコピー（以後は手元の編集を上書きしない）
[ -e "$DEST/config.toml" ] || install -Dm644 result/share/kuda/config.example.toml "$DEST/config.toml"
mkdir -p "$DEST/prompts"
cp -rn --no-preserve=mode result/share/kuda/prompts/. "$DEST/prompts/"
```

更新時は `nix build` と `kuda.exe`、`kudaw.exe` のコピーだけを再実行します。タスクの実行中は exe がロックされてコピーに失敗することがあるので、その場合は数秒おいて再実行してください。

### Linux

```bash
# バイナリはNixプロファイルに入れる（更新は nix profile upgrade kuda）
nix profile install .#kuda

# 設定とプロンプト（初回のみ）
nix build .#kuda
CONF="${XDG_CONFIG_HOME:-$HOME/.config}/kuda"
mkdir -p -m 0700 "$CONF/prompts"
[ -e "$CONF/config.toml" ] || install -m644 result/share/kuda/config.example.toml "$CONF/config.toml"
cp -rn --no-preserve=mode result/share/kuda/prompts/. "$CONF/prompts/"
```

データ・状態・ログのディレクトリは、初回の `check` で自動作成されます（Linuxでは `0700`）。ログは日付でローテーションし、既定で14日分を残します。

## 設定ファイル

`config.toml` は、全体設定・LLMバックエンド・watch の3部構成です。スケジュール起動型では、watch ごとの `interval` は「前回の probe から何秒経っていれば実行するか」として扱います。そのため、スケジューラの起動間隔（5分）より短い値は意味がありません。

### config.toml の例

```toml
[general]
log_level = "info"
log_retention_days = 14

# --- LLMバックエンド ---
[backends.claude_code]
command = "claude"              # PATH 上に無ければフルパス
max_turns = 20

[backends.codex]
command = "codex"

[backends.local]
endpoint = "http://127.0.0.1:11434/v1"   # Ollama の OpenAI 互換 API
model = "qwen2.5:7b"
mode = "analyze_only"          # ツール実行なしで事件ファイルだけを分析

# --- 監視 ---
[[watch]]
name = "network-reachability"
interval = "5m"

  [watch.probe]
  kind = "tcp"
  targets = ["1.1.1.1:443", "8.8.8.8:53", "gateway"]
  timeout = "3s"

  [watch.baseline]
  metrics_retention = "7d"
  aggregate_by = "weekday_hour"
  min_samples = 30                # これ未満の時間帯は全体平均で代用
  snapshot_collectors = ["adapters", "routes", "dns_config", "traceroute:1.1.1.1"]
  snapshot_interval = "6h"
  keep_good_snapshots = 5

  [watch.trigger]
  when = "loss >= 0.5 || rtt_p50 > baseline.rtt_p95 * 2"
  consecutive = 3
  cooldown = "30m"
  recover_notify = true

  [watch.diagnose]
  backend = "claude_code"
  fallback = "local"
  prompt_file = "prompts/network.md"
  allowed_commands = ["tracert", "traceroute", "ping", "ipconfig", "nslookup", "dig", "Test-NetConnection", "Get-NetAdapter"]
  max_duration = "5m"
```

`gateway` は、実行時のデフォルトゲートウェイに置き換えられる特別なターゲットです。`kind = "tcp"` でポートを省くと ICMP echo で確かめ、通らなければ 53/80/443 への接続を試します（接続拒否も到達可能として扱います）。`gateway:80` のようにポートも指定できます。ベースラインの `rtt_p95` は、データが貯まるまで（`min_samples` 未満の間）条件式で使えません。最初の数日は `loss` 系の条件だけが効きます。

### prompts/network.md の例

プロンプトには、事件ディレクトリのパスと出力形式を必ず含めます。`{{incident_dir}}` などのプレースホルダはハーネスが展開します。

```markdown
あなたはこのPCのネットワーク障害を調査する担当です。

調査材料は {{incident_dir}} にあります。まず summary.md と diff.md を読んでください。
- current.json / last_known_good.json: 異常時と最後の正常時のスナップショット
- metrics.csv: 直近の probe 結果と同時間帯のベースライン

必要に応じて読み取り専用のコマンドで追加調査してください。
設定の変更・再起動・ファイル削除は行わないでください。
OS: {{os}} / 発生開始: {{since}}

次の形式でMarkdownを出力してください。
## 症状
## 切り分け結果（どの層で止まっているか: 端末 / LAN / ゲートウェイ / ISP / 宛先 / DNS）
## 推定原因（確度つき）
## 推奨アクション
## 実行したコマンド
```

設定を書いたら、構文と参照先（プロンプトファイル、バックエンドのコマンド）を検証します。

```
kuda check-config
```

## LLMバックエンドの準備

使うバックエンドを、スケジューラが実行するのと同じユーザーでセットアップします。それぞれ単体で動くことを確認してから、ハーネスに組み込みます。

### Claude Code（既定）

1. Claude Code をインストールし、`claude` を一度対話起動してログインする。Windowsでは Git for Windows（Git Bash）も必要です。
2. ヘッドレス実行が通ることを確認する。

```
claude -p "tracert -d -h 5 1.1.1.1 を実行して結果を要約して" --allowedTools "Bash(tracert:*)" --output-format json
```

ハーネスは内部で、事件ディレクトリを作業ディレクトリにして次の形で起動します。`allowed_commands` が `--allowedTools` に変換され、事件ディレクトリの読み取り（`Read(./**)`）だけが追加で許可されます。プロンプトは標準入力で渡します。

```
claude -p --output-format json --strict-mcp-config --setting-sources project --permission-mode dontAsk --max-turns 20 --tools Read Bash --allowedTools "Read(./**)" "Bash(tracert:*)" ...
```

使えるツールを Read と Bash に絞り、MCP サーバー、ユーザー設定の allow ルールとフックを持ち込みません。許可外の操作は確認なしで拒否されます。ただし、Claude Code が読み取り専用と判定するコマンド（`whoami` など）は許可リストに無くても実行されます。`--bare` は OAuth のログインを読まなくなるため使いません。

Windowsでは Claude Code のシェルが Git Bash になるため、`Test-NetConnection` などのPowerShellコマンドレットは `powershell -NoProfile -Command ...` 経由で実行されます。許可ルールもその形に合わせ、`Bash(powershell -NoProfile -Command Test-NetConnection:*)` のように展開してください。

### Codex

1. Codex CLI をインストールし、`codex login` でログインする。
2. `codex exec` で同様のテストプロンプトが通ることを確認する。

Codex はサンドボックスの設定によって、実行するコマンドのネットワークアクセスが制限される場合があります。`tracert` などが失敗しないか、この確認の段階で見ておいてください。

### ローカルLLM（fallback 用）

OpenAI互換のAPIを持つサーバーなら何でも使えます。既定の `analyze_only` モードでは、ツール実行をせず事件ファイルの分析だけを行います。

- **Ollama**: インストール後に `ollama pull qwen2.5:7b` を実行する。エンドポイントは `http://127.0.0.1:11434/v1` です。
- **llama.cpp**: `llama-server -m <model>.gguf --port 8080` で起動する。エンドポイントは `http://127.0.0.1:8080/v1` です。

RTX 4060 Laptop（VRAM 8GB）では、7〜8Bクラスの4bit量子化モデルがVRAMに収まります。

ローカルLLMサーバーを常駐させるとアイドル時のメモリ要件と衝突します。Ollama はモデルを一定時間（既定5分）でアンロードしますが、サーバープロセス自体は残ります。気になる場合は、ハーネスが調査時にだけサーバーを起動するよう `[backends.local]` に `start_command` を追加する実装も検討してください。

### 疎通確認

バックエンドごとに、到達性と認証を確認します。

```
kuda check-backends
```

各バックエンドについて `available()` の結果（コマンドの有無、ローカルエンドポイントの応答）が表示されます。

## 手動での動作確認

スケジューラに登録する前に、手動で1サイクルずつ確かめます。最後に、到達不能なアドレスを使って擬似障害を起こし、調査からレポート生成までを通します。

1. 1回分の監視を実行し、probe 結果とトリガー判定を確認する。

```
kuda check --verbose
```

2. スナップショットを強制取得し、collector がすべて成功するか確認する。初回の `last_known_good` もこれで作られます。

```
kuda snapshot --force
```

3. 状態を確認する。サンプル数、ベースラインの値、最後のスナップショット時刻、クールダウン状態が表示されます。

```
kuda status
```

4. 事件ディレクトリだけを生成し、LLMは呼ばずに中身を確認する（`summary.md` と `diff.md` が読める内容になっているか）。

```
kuda diagnose --watch network-reachability --dry-run
```

5. 実際にLLMで調査させ、レポートを確認する。バックエンドを切り替えて、fallback 先の動作も見ておきます。

```
kuda diagnose --watch network-reachability
kuda diagnose --watch network-reachability --backend local
```

6. 擬似障害で、トリガーから調査までを通しで確認する。`config.toml` に、到達不能なドキュメント用アドレス（TEST-NET-1）を宛先にした試験用 watch を一時的に追加します。

```toml
[[watch]]
name = "test-unreachable"
interval = "5m"
  [watch.probe]
  kind = "tcp"
  targets = ["192.0.2.1:443"]
  timeout = "2s"
  [watch.trigger]
  when = "loss >= 0.5"
  consecutive = 2
  cooldown = "10m"
  [watch.diagnose]
  backend = "claude_code"
  prompt_file = "prompts/network.md"
  allowed_commands = ["tracert", "traceroute", "ping"]
```

`kuda check --force` を2回実行し（`--force` が無いと `interval` が経つまで2回目の probe は飛ばされます）、2回目で発火して `reports/test-unreachable/` にレポートができれば成功です。確認後、この watch は削除してください。

## スケジューラ登録

5分間隔で `kuda check` を起動します。LLMの調査は数分かかるため、`check` は調査プロセスを**親から切り離して**起動し、自身はすぐ終了するように実装します。そうしないと、調査中に次の probe が止まったり、スケジューラが調査プロセスごと終了させたりします。

### Windows: タスクスケジューラ

タスクスケジューラはタスクのプロセスをジョブオブジェクトに入れて管理します。調査プロセスは `CREATE_BREAKAWAY_FROM_JOB | DETACHED_PROCESS | CREATE_NO_WINDOW` を付けて起動してください。

登録は次のPowerShellで行います（一度だけ実行、管理者権限は不要）。

```powershell
$exe = "$env:LOCALAPPDATA\kuda\bin\kudaw.exe"
$action = New-ScheduledTaskAction -Execute $exe -Argument "check"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
  -RepetitionInterval (New-TimeSpan -Minutes 5)
$logon = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet `
  -MultipleInstances IgnoreNew `
  -ExecutionTimeLimit (New-TimeSpan -Minutes 2) `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -StartWhenAvailable
Register-ScheduledTask -TaskName "kuda" -Action $action `
  -Trigger $trigger, $logon -Settings $settings
```

設定の意図は次のとおりです。

- `MultipleInstances IgnoreNew`: 前回の `check` が残っていれば、新しい起動をスキップする
- `ExecutionTimeLimit 2分`: `check` 自体（probe と判定）が固まったときの保険。調査プロセスは切り離しているので、この制限の対象外です
- バッテリー関連: ノートPCでもバッテリー駆動中に止めない
- `AtLogOn` トリガー: ログオン直後から監視を始める

登録できたら、すぐに1回実行して結果を確認します。

```powershell
Start-ScheduledTask -TaskName "kuda"
Get-ScheduledTaskInfo -TaskName "kuda"   # LastTaskResult が 0 なら成功
```

### Linux: systemd user timer

systemd はサービス終了時に、同じ cgroup に残ったプロセスを既定で終了させます。そこで、調査プロセスは `systemd-run --user --unit=kuda-diagnose-<watch名> ...` で別ユニットとして起動するように実装します。この方法なら、同名ユニットが既に動いているときは起動に失敗するので、多重起動防止にもなります。

ユニットファイルは `$XDG_CONFIG_HOME/systemd/user/`（既定 `~/.config/systemd/user/`）に置きます。systemd の user インスタンスもこの変数に従います。

`kuda.service`:

```ini
[Unit]
Description=Kuda monitoring run

[Service]
Type=oneshot
ExecStart=%h/.nix-profile/bin/kuda check
TimeoutStartSec=120
Nice=10
IOSchedulingClass=idle
```

Nix の `use-xdg-base-directories` を有効にしている場合、プロファイルは `~/.local/state/nix/profile` になります。そのときは `ExecStart=%h/.local/state/nix/profile/bin/kuda check` に変えてください。

`kuda.timer`:

```ini
[Unit]
Description=Run Kuda every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
AccuracySec=5s

[Install]
WantedBy=timers.target
```

有効化します。

```bash
systemctl --user daemon-reload
systemctl --user enable --now kuda.timer
loginctl enable-linger "$USER"   # ログアウト中も動かす場合
systemctl --user list-timers kuda.timer
```

ICMP の probe を使う場合は、非特権の ping ソケットが許可されているか確認します。許可範囲にユーザーのグループIDが含まれていない場合は、`sysctl` で範囲を広げるか、TCP の probe を使ってください。

```bash
sysctl net.ipv4.ping_group_range
```

## 運用

日常的には `kuda status` とレポートディレクトリを見るだけで足ります。登録後の最初の1週間は、誤発火の頻度を見ながら `consecutive` と条件式を調整してください。

### 確認するもの

- **状態**: `kuda status` で、各 watch の直近結果、ベースライン、クールダウン残り時間を確認する
- **レポート**: `reports/<watch名>/<日時>.md`。使ったバックエンド、所要時間、実行したコマンドも記録されます
- **事件ディレクトリ**: `incidents/` の中身はレポートの根拠です。既定で30日分を残します
- **ログ**: `logs/kuda-<日付>.log`

### トラブルシューティング

| 症状 | よくある原因 | 対処 |
| --- | --- | --- |
| タスクは動くのに記録が増えない | `KUDA_HOME` や作業ディレクトリが手動実行時と違う | ログの先頭に出る解決済みパスを確認し、必要なら `KUDA_HOME` をタスクの環境に設定する |
| 調査が途中で消える | 調査プロセスが切り離されていない | Windows は `CREATE_BREAKAWAY_FROM_JOB`、Linux は `systemd-run` 経由になっているか確認する |
| LLMが「認証されていない」で失敗する | タスクが別ユーザー・別プロファイルで動いている | スケジューラの実行ユーザーで `claude` / `codex` にログインし直す |
| 一瞬の瞬断で何度も発火する | `consecutive` が小さい、またはベースラインがまだ無い | `consecutive` を増やし、データが貯まるまで `loss` の閾値を上げる |
| Windowsで黒い窓が一瞬出る | タスクが `kuda.exe` を起動している、または外部コマンドに `CREATE_NO_WINDOW` が付いていない | タスクの実行ファイルを `kudaw.exe` にし、`tracert` などの子プロセス起動にもフラグを付ける |
| PowerShellで実行しても何も表示されない | `kudaw.exe` を実行している | 手動の実行には `kuda.exe` を使う |
| Linuxで ICMP の probe が常に失敗する | 非特権 ping ソケットが不許可 | `net.ipv4.ping_group_range` を確認するか、TCP の probe に切り替える |
| 完全断の調査がいつも失敗する | クラウドLLMに届かない | `fallback = "local"` が設定されていて、ローカルサーバーが起動しているか確認する |

### 一時停止とアンインストール

Windows:

```powershell
Disable-ScheduledTask -TaskName "kuda"                    # 一時停止
Unregister-ScheduledTask -TaskName "kuda" -Confirm:$false  # 削除
Remove-Item -Recurse "$env:LOCALAPPDATA\kuda"              # データごと削除する場合
```

Linux:

```bash
UNITS="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
systemctl --user stop kuda.timer                 # 一時停止
systemctl --user disable --now kuda.timer        # 削除
rm "$UNITS"/kuda.{service,timer}
systemctl --user daemon-reload
nix profile remove kuda

# データごと削除する場合
rm -r "${XDG_CONFIG_HOME:-$HOME/.config}/kuda" \
      "${XDG_STATE_HOME:-$HOME/.local/state}/kuda" \
      "${XDG_DATA_HOME:-$HOME/.local/share}/kuda"
```
