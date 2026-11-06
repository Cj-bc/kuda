// リリースビルドではタスク起動のたびにコンソール窓が出ないよう GUI サブシステムにする
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    kuda::main()
}
