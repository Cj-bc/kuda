# Kuda アーキテクチャ

コードを変える人向けの設計メモです。ビルド、配置、スケジューラ登録などの運用は [handoff.md](handoff.md) にあります。プロセス監視の設計の根拠は [process-watch-plan.md](process-watch-plan.md) にあります。

## 1. 処理の流れ

### 1.1 check の 1 サイクル

`kuda check` は watch ごとに次の順で処理します（`commands.rs`）。

1. `kuda.lock` を取る。他の `check` が持っていれば、何もせず終了する
2. watch ごとに、前回の probe から `interval` が経っていなければ飛ばす（スケジューラの早まりを 1 割、最大 30 秒まで許す）
3. **probe**: 設定された種類（tcp / icmp / dns / http / command / process）で観測し、指標（`loss`、`rtt_p50` など）を作る
4. **classify（process のみ）**: 列挙したプロセスを既知の集合と照らし、`unknown`、`masquerade`、`missing` などの指標を足す
5. **stats**: 時間帯別の統計（p50/p95）を引き、`baseline.*` の変数にする
6. **trigger**: 指標と変数に対して条件式を評価し、連続回数とクールダウンを数える
7. 結果を SQLite に記録する。条件式が成立せず probe も全滅でない（正常な）回だけ、統計に加え、`snapshot_interval` が過ぎていればスナップショットも取る
8. 発火したら **incident**（事件ディレクトリ）を作り、**diagnose** を切り離して起動する。`check` 自身は待たずに終了する

process の分類には順序の制約があります。学習してよいのは正常な回だけですが、正常かどうかは条件式で決まり、式の変数は分類の結果に依存します。そのため、まず学習する前提で分類し、式が成立したら学習しない前提でやり直します（`classify_processes`）。

### 1.2 なぜ短命のスケジュール起動なのか

- 常駐しないので、アイドル時のメモリ消費が実質ゼロになる
- 状態はすべて SQLite とファイルにあり、プロセスの寿命と無関係になる。落ちても次の起動が続きを処理する
- 常駐デーモンの管理（自動起動、再起動、更新時の差し替え）を OS のスケジューラに任せられる

その代わり、次の制約があります。

- `check` は数秒で終わらなければならない。数分かかる LLM の調査は、`check` の子ではなく**切り離したプロセス**として起動する（`detach.rs`）。スケジューラは、タスクの終了時に残ったプロセスも止めるため
- 次の `check` は調査の途中でも始まる。そのため、`check` と `snapshot` と調査プロセスは同時に動きうる前提で DB を設計している（3.3 節）
- 5 分間隔のポーリングなので、5 分より短い現象は見えない

## 2. モジュール構成

依存の向きは、上が下を使います。`config`、`metrics`、`os`、`time` はほぼ葉で、他のモジュールから広く使われます（`config` は式の型として `trigger::Expr`、パス型として `paths` も参照します）。

| 層 | モジュール | 持っているもの |
| --- | --- | --- |
| 入口 | `lib.rs`、`main.rs`、`bin/kudaw.rs` | clap の CLI 定義とサブコマンドの振り分け。`kuda` と `kudaw` は同じ `lib.rs` を呼ぶ |
| 組み立て | `commands.rs` | サブコマンドの本体。1 回の check を `Observation { run, metrics, stats, classification }` として `observe(...)` で作り、`apply(...)` で反映する（記録、正常なら学習とスナップショット、トリガー、発火） |
| 判定 | `trigger.rs` | 条件式のパースと評価、連続回数とクールダウンの状態遷移（`TriggerState`、`advance`） |
| 判定 | `baseline.rs` | 時間帯別 p50/p95 の統計。対数ビンのヒストグラムとして蓄積する |
| 判定 | `known_set.rs` | プロセスの識別キーの正規化、フラグ判定（user_writable、masquerade）、既知の集合との分類 |
| 観測 | `probe/` | 疎通確認とプロセスの列挙（`probe/process.rs`）。判定や学習はしない |
| 観測 | `collector/` | スナップショットの収集（adapters、routes、dns_config、traceroute）と、その結果の型（`collector/snapshot.rs`） |
| 永続化 | `store/` | SQLite。テーブルごとにサブモジュール（metrics、hist、snapshot、state、identities）に分け、`schema.rs` に移行を持つ |
| 調査 | `incident/` | 事件ディレクトリの生成（`mod.rs`）と、スナップショットの差分（`diff.rs`） |
| 調査 | `diagnosis/` | LLM バックエンド（`claude_code`、`codex`、`local`）の選択、fallback、レポートの保存 |
| 調査 | `detach.rs`、`investigation.rs`、`lock.rs` | 調査プロセスの切り離し起動、実行中の調査の記録、多重起動防止 |
| 部品 | `exec.rs` | 外部コマンドの起動。タイムアウト、子孫プロセスの回収、Windows で窓を出さないこと |
| 部品 | `notify.rs`、`logging.rs`、`paths.rs` | デスクトップ通知、日付ローテーションのログ、OS 別のディレクトリ解決 |
| 葉 | `config.rs` | TOML の形（`Raw*`）を検証して、使う側の型（`Watch`、`Probe` など）にする。`[watch.baseline]` の 1 つの表を、統計・スナップショット・プロセスの学習期間に分ける |
| 葉 | `metrics.rs` | `Variables`（`BTreeMap<String, f64>`）、指標と変数の名前の定数、ベースラインの系列表、`variables_for(ProbeKind)`（`trigger.rs` から移した） |
| 葉 | `os.rs`、`time.rs` | OS の区別（規則を決める関数は実行中の OS を自分で調べず `Os` を受け取る。Windows の規則のテストを Linux でも走らせるため）、時刻の表記 |

主な依存の向きは次のとおりです。

- `commands` は他のほとんどを使うが、他から `commands` は使われない
- `store` は `probe`（結果の型）と `collector`（スナップショットの型）、`trigger`（状態の型）に依存する。`store` は SQL を持つだけで、判定はしない
- `baseline` と `known_set` は `store` を読み書きして統計と分類を行う。判定の規則そのもの（正規化、フラグ、glob）は純関数にして、環境変数や OS を引数で受け取る
- `incident` は `baseline`、`collector`、`probe`、`store` の型を読んで、ファイルを書く
- `diagnosis` は `incident` の出力を読むだけで、`store` を使わない

## 3. データモデル

SQLite（`kuda.db`、WAL モード）です。版は `PRAGMA user_version` で持ち、`store/schema.rs` の `MIGRATIONS` を 1 段ずつ適用します。版の確認と適用は同じ書き込みトランザクションで行い、別プロセスと二重に適用しません。新しい kuda が上げた DB は、古い kuda では開けません（ダウングレード非対応）。

### 3.1 テーブル

| テーブル | 内容 | 書き込み元 |
| --- | --- | --- |
| `probe_results` | ターゲットごとの結果（成否、RTT、値、エラー） | check |
| `metrics` | probe ごとの指標（`name`、`value`）。`metrics_retention` を超えたものは消す | check |
| `baseline_hist` | 時間帯別の分布（対数ビンのヒストグラム）。`aggregate_by` ごとに分け、`metrics_retention` を超えて蓄積する | check（正常な回のみ） |
| `snapshots` | スナップショットの取得履歴。失敗した collector も含む。新しい `keep_good_snapshots` 件だけ残す | `Store::record_snapshot` |
| `known_good` | collector ごとの最後に成功したデータ（`watch`、`collector`、`ts`、`data`） | `Store::record_snapshot` |
| `watch_state` | watch ごとの状態（3.2 節） | 列ごとに異なる |
| `process_identities` | プロセスの既知の集合。`status` は `known`、`pending`、`reported` | check |

### 3.2 watch_state の列と書き込み元

`watch_state` は 1 つの行を、書き込み元が異なる 3 組の列に分けて使います。

| 列 | 書く人 | 内容 |
| --- | --- | --- |
| `last_probe`、`streak`、`since`、`last_fired`、`active` | check だけ（`save_state`。型は `ProbeState`） | 最後の probe の時刻と、トリガーの状態 |
| `last_snapshot`、`last_complete_snapshot`、`last_snapshot_complete` | `Store::record_snapshot` だけ（型は `SnapshotState`） | 最後の取得の時刻と、全 collector が成功したか |
| `learning_started` | check（`start_learning`） | プロセスの学習期間の起点。最初に分類した時刻 |

どの書き込みも `INSERT ... ON CONFLICT DO UPDATE` で、自分の列だけを更新します。

### 3.3 なぜ check と snapshot が並行してよいのか

`kuda snapshot` は `check` のロックを取りません。また、調査中にも次の `check` が始まります。それでも壊れないように、次のようにしています。

- `snapshot` は、スナップショットの記録以外は何も書かない。読み込んだ状態全体を書き戻すと、収集の最中に `check` が保存した `last_probe` などを巻き戻してしまうため
- `check` の `save_state` は、スナップショット側の列に触れない。`check` が先に読んだ状態を後から書いても、`snapshot` の更新を巻き戻さない
- `record_snapshot` は 1 つの書き込みトランザクションの中で、履歴、`known_good`、`watch_state` を更新する
- `known_good` は `excluded.ts >= known_good.ts` のときだけ上書きし、`last_snapshot` は時刻を戻さない。収集開始の早い側があとから完了しても、新しい記録を古いもので置き換えない
- 接続には `busy_timeout`（10 秒）を付け、同時に開いても待ち合わせで済むようにする

## 4. スナップショットの JSON 形式

スナップショットは次の形で、DB（`snapshots.data`）と事件ディレクトリ（`current.json`）に書きます。

```json
{"collectors":{"dns_config":{"error":"command not found","ok":false},
               "routes":{"data":{"n":1},"ok":true}},
 "taken_at":100}
```

比較基準（`last_known_good.json`）は、collector ごとに `{"data": ..., "ok": true, "taken_at": ...}` を持つ形です。`known_good.data` には、その collector の `data` だけを入れます。

**この形は変えてはいけません。** 次のものが形に依存しているためです。

- 版 3 の移行 SQL が、既存の `snapshots.data` を `json_each` で読み、`$.collectors`、`ok`、`data` を取り出して `known_good` を作る。移行 SQL は既存の DB に対して今後も走る
- LLM に渡すプロンプト（`prompts/*.md`）が、`current.json` と `last_known_good.json` の形を前提に読ませる
- 保存済みの DB と、保持期間内の事件ディレクトリを、新しい版でも読めなければならない

型（`collector/snapshot.rs`）は、型を導入する前の JSON と同じ形で読み書きします。キーの順も旧来（昇順）に合わせるため、フィールドを昇順に宣言し、往復のテストで固定しています。形を変えるときは、新しい移行を末尾に足し、旧形式を読めるままにしてください。

## 5. 用語

### 5.1 baseline（ベースライン）

この語は、コードの中で 4 つの別のものを指します。

| どれか | 場所 | 内容 |
| --- | --- | --- |
| TOML の `[watch.baseline]` | `config.rs` | 設定の表の名前。統計（`metrics_retention`、`aggregate_by`、`min_samples`）、スナップショット（`snapshot_collectors`、`snapshot_interval`、`keep_good_snapshots`）、プロセスの `learn_for` が 1 つの表に並ぶ。使う側が別なので、`into_watch` が分ける |
| 時間帯別の統計 | `baseline.rs` | 時間帯ごとの p50/p95。条件式の `baseline.rtt_p95` などの変数になる。データが足りない（`min_samples` 未満の）間は使えない |
| `last_known_good` | `store/snapshot.rs`、`known_good` テーブル | collector ごとに最後に成功したスナップショットのデータ。事件の `diff.md` で、異常時の状態の比較基準になる |
| プロセスの既知の集合 | `known_set.rs`、`process_identities` テーブル | `known` のプロセス識別キーの集合。`learn_for` の期間に見たものを `known` にする |

`kuda status` の `baseline` 行は 2 番目（時間帯別の統計）です。

### 5.2 そのほかの用語

| 用語 | 意味 |
| --- | --- |
| watch | 設定の `[[watch]]`。名前を持ち、probe、トリガー、調査の設定をまとめた監視の単位 |
| probe | 1 回の観測。`kind` で種類が決まる。結果は `ProbeRun`（ターゲットごとの結果と、そこから作る指標） |
| collector | スナップショットを構成する、システム状態の収集器（adapters、routes、dns_config、traceroute）。probe とは別物 |
| snapshot | 全 collector を 1 回実行した結果。collector ごとに成功か失敗かを持つ |
| incident（事件） | 発火の根拠をまとめたディレクトリ（`summary.md`、`diff.md`、`current.json`、`last_known_good.json`、`metrics.csv`、`incident.json`）。調査の入力で、レポートの根拠でもある |
| report（レポート） | 調査の出力。`reports/<watch>/<事件ID>.md`。使ったバックエンドと所要時間も書く。回復のお知らせ（`-recovered.md`）も同じ場所に置く |
| 発火 | トリガー条件が連続回数を満たし、クールダウン中でもないこと。事件を作って調査を起動する |

## 6. 「調査が走っている」の 3 つの表現

調査（`kuda diagnose`）が走っていることは、目的の違う 3 つの方法で表しています。互いに代用できません。

| 表現 | 場所 | 何のためか |
| --- | --- | --- |
| 調査ごとのロックファイル | `kuda-diagnose-<watch>.lock`（ロックのディレクトリ）。`diagnose` が `hold_until_exit` で取る | 同じ watch の調査を 2 つ同時に走らせない。OS が終了時に解放するので、異常終了しても残らない。Windows を含む全 OS で効く |
| systemd のユニット名 | `kuda-diagnose-<watch>`（Linux のみ。`systemd-run --user --unit=...`） | 調査を別ユニットにして、`check` のサービス終了時に cgroup ごと止められないようにする。同名ユニットが動いていれば起動に失敗するので、起動する側の多重起動防止にもなる。`XDG_RUNTIME_DIR` や `systemd-run` が無ければ、プロセスグループを分けるだけにする |
| `investigating-<watch>` の記録 | 状態ディレクトリ（`data_dir`）。内容は `PID 起動時刻`。`investigation.rs` | process watch が、調査プロセスとその子孫を未知のプロセスとして数えないようにする。調査は切り離されていて、親子関係でたどれないため。PID の再利用に備えて起動時刻も照合する。調査の終了時に消すが、異常終了で残っても、生きていないものとして無視する |

1 つ目は排他、2 つ目は切り離し、3 つ目は監視の対象からの除外です。

## 7. LLM の境界

kuda の LLM への権限は、設定とコードで絞っています。

- **1 回の調査で試すのは、主バックエンドと fallback を 1 度ずつだけ。** それぞれ `max_duration` で打ち切る（`diagnosis/mod.rs`）。無制限に再試行しない
- **`allowed_commands` は OS ごとに分ける。** `windows` と `linux` を別々に持ち、実行中の OS の分だけをバックエンドに渡す。省略した OS では、コマンドを 1 つも許可しない
- **claude_code**（`diagnosis/claude_code.rs`）:
  - 作業ディレクトリは事件ディレクトリ。プロンプトは標準入力で渡す
  - `--tools` は Read と、許可コマンドがあるときの Bash だけ。許可は `--allowedTools` に、`Read(./**)` と `Bash(<command>:*)` として渡す
  - `--strict-mcp-config`（MCP サーバーを読まない）、`--setting-sources ""` と `--restricted`（user / project / local の設定を読まない）、`--permission-mode dontAsk`（許可外は確認せず拒否）を付ける。事件ディレクトリは第三者から受け取ることもあり、そこのフックや allow ルールで境界の外のコマンドが動くのを防ぐため
  - Windows では、PowerShell のコマンドレットを `powershell -NoProfile -Command ...` の形の許可ルールに変える
  - `--bare` は OAuth のログインを読まなくなるので使わない
- **codex**（`diagnosis/codex.rs`）: コマンド単位の許可リストが無いので、`--sandbox read-only` を境界にする。最終メッセージは、毎回新しく作る一時ディレクトリに書かせる（事件ディレクトリには書かせない）
- **local**（`diagnosis/local.rs`）: OpenAI 互換 API。`mode` は `analyze_only` だけで、ツールは渡さない。読むのは事件ディレクトリの `summary.md`、`diff.md`、`metrics.csv` だけで、通常のファイルに限り（シンボリックリンクは辿らない）、1 つ 24 KiB で切る
- 事件ディレクトリの中身は、LLM にとっては指示ではなく調べる材料として扱う
- 調査の結果は、自動では何にも反映しない。レポートを書くだけ
