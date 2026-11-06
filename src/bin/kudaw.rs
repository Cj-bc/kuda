//! スケジューラから起動する `kuda`。Windows ではタスク起動のたびにコンソール窓が出ないよう
//! GUI サブシステムにする。標準出力がコンソールに繋がらないので、手動の実行には `kuda` を使う。
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    kuda::main()
}
