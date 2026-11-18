//! OS ごとに規則が変わる処理で使う、OS の区別。
//!
//! 規則を決める関数は実行中の OS を自分で調べず、この値を受け取る。こうしておくと、
//! Windows の規則のテストを Linux 上でも（その逆も）走らせられる。
//! 実行中の OS でしか動かない処理（Win32 API や外部コマンドの選択）は `cfg` で分ける。

/// 実行中の OS とは限らない（テストのため）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Linux,
}

impl Os {
    pub fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else {
            Os::Linux
        }
    }

    pub fn separator(self) -> char {
        match self {
            Os::Windows => '\\',
            Os::Linux => '/',
        }
    }
}
