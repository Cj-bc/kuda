//! 発火条件の式と、連続回数・クールダウンの判定。
//!
//! 式は `loss >= 0.5 || rtt_p50 > baseline.rtt_p95 * 2` のような形で、
//! 値が無い変数（データ不足のベースラインや、全滅時の RTT）を含む比較は
//! 「不明」になる。最終結果が不明なら発火しない。

use crate::config::Trigger;
use serde::Deserialize;
use std::collections::BTreeMap;

/// 条件式で使える変数
pub const VARIABLES: [&str; 11] = [
    "loss",
    "rtt_p50",
    "rtt_p95",
    "rtt_max",
    "value",
    "baseline.rtt_p50",
    "baseline.rtt_p95",
    "baseline.loss_p50",
    "baseline.loss_p95",
    "baseline.value_p50",
    "baseline.value_p95",
];

pub type Variables = BTreeMap<String, f64>;

#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "String")]
pub struct Expr {
    source: String,
    root: Cond,
}

#[derive(Debug, Clone, PartialEq)]
enum Cond {
    Or(Box<Cond>, Box<Cond>),
    And(Box<Cond>, Box<Cond>),
    Not(Box<Cond>),
    Cmp(CmpOp, Num, Num),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CmpOp {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Ne,
}

#[derive(Debug, Clone, PartialEq)]
enum Num {
    Literal(f64),
    Var(String),
    Neg(Box<Num>),
    Arith(ArithOp, Box<Num>, Box<Num>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Number(f64),
    Ident(String),
    Op(&'static str),
}

const OPERATORS: [&str; 15] = [
    "||", "&&", ">=", "<=", "==", "!=", ">", "<", "!", "+", "-", "*", "/", "(", ")",
];

fn tokenize(source: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut rest = source.trim_start();
    while let Some(c) = rest.chars().next() {
        if let Some(op) = OPERATORS.iter().find(|op| rest.starts_with(**op)) {
            tokens.push(Token::Op(op));
            rest = &rest[op.len()..];
        } else if c.is_ascii_digit() {
            let end = rest
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .unwrap_or(rest.len());
            let number = rest[..end]
                .parse()
                .map_err(|_| format!("invalid number: {}", &rest[..end]))?;
            tokens.push(Token::Number(number));
            rest = &rest[end..];
        } else if c.is_ascii_alphabetic() || c == '_' {
            let end = rest
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.')
                .unwrap_or(rest.len());
            tokens.push(Token::Ident(rest[..end].to_string()));
            rest = &rest[end..];
        } else {
            return Err(format!("unexpected character: {c:?}"));
        }
        rest = rest.trim_start();
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn eat(&mut self, op: &str) -> bool {
        let matched = matches!(self.tokens.get(self.pos), Some(Token::Op(o)) if *o == op);
        if matched {
            self.pos += 1;
        }
        matched
    }

    fn or(&mut self) -> Result<Cond, String> {
        let mut left = self.and()?;
        while self.eat("||") {
            left = Cond::Or(Box::new(left), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Cond, String> {
        let mut left = self.unary()?;
        while self.eat("&&") {
            left = Cond::And(Box::new(left), Box::new(self.unary()?));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Cond, String> {
        if self.eat("!") {
            return Ok(Cond::Not(Box::new(self.unary()?)));
        }
        // "(" は論理式の括弧か算術の括弧か読むまで分からないので、比較を先に試す
        let start = self.pos;
        match self.comparison() {
            Ok(cond) => Ok(cond),
            Err(error) => {
                self.pos = start;
                if !self.eat("(") {
                    return Err(error);
                }
                let inner = self.or()?;
                if !self.eat(")") {
                    return Err("expected ')'".to_string());
                }
                Ok(inner)
            }
        }
    }

    fn comparison(&mut self) -> Result<Cond, String> {
        let left = self.sum()?;
        let ops = [
            (">=", CmpOp::Ge),
            ("<=", CmpOp::Le),
            ("==", CmpOp::Eq),
            ("!=", CmpOp::Ne),
            (">", CmpOp::Gt),
            ("<", CmpOp::Lt),
        ];
        for (text, op) in ops {
            if self.eat(text) {
                return Ok(Cond::Cmp(op, left, self.sum()?));
            }
        }
        Err("expected a comparison such as `loss >= 0.5`".to_string())
    }

    fn sum(&mut self) -> Result<Num, String> {
        let mut left = self.product()?;
        loop {
            let op = if self.eat("+") {
                ArithOp::Add
            } else if self.eat("-") {
                ArithOp::Sub
            } else {
                return Ok(left);
            };
            left = Num::Arith(op, Box::new(left), Box::new(self.product()?));
        }
    }

    fn product(&mut self) -> Result<Num, String> {
        let mut left = self.atom()?;
        loop {
            let op = if self.eat("*") {
                ArithOp::Mul
            } else if self.eat("/") {
                ArithOp::Div
            } else {
                return Ok(left);
            };
            left = Num::Arith(op, Box::new(left), Box::new(self.atom()?));
        }
    }

    fn atom(&mut self) -> Result<Num, String> {
        if self.eat("-") {
            return Ok(Num::Neg(Box::new(self.atom()?)));
        }
        if self.eat("(") {
            let inner = self.sum()?;
            if !self.eat(")") {
                return Err("expected ')'".to_string());
            }
            return Ok(inner);
        }
        let token = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        match token {
            Some(Token::Number(n)) => Ok(Num::Literal(n)),
            Some(Token::Ident(name)) if VARIABLES.contains(&name.as_str()) => Ok(Num::Var(name)),
            Some(Token::Ident(name)) => Err(format!(
                "unknown variable: {name} (available: {})",
                VARIABLES.join(", ")
            )),
            Some(Token::Op(op)) => Err(format!("unexpected {op:?}")),
            None => Err("unexpected end of expression".to_string()),
        }
    }
}

impl TryFrom<String> for Expr {
    type Error = String;

    fn try_from(source: String) -> Result<Self, String> {
        let tokens = tokenize(&source)?;
        let mut parser = Parser { tokens, pos: 0 };
        let root = parser.or()?;
        if parser.pos != parser.tokens.len() {
            return Err(format!(
                "unexpected trailing input in {source:?} at token {}",
                parser.pos + 1
            ));
        }
        Ok(Self { source, root })
    }
}

impl Expr {
    pub fn source(&self) -> &str {
        &self.source
    }

    /// 不明（判定材料が足りない）場合は発火させない
    pub fn matches(&self, vars: &Variables) -> bool {
        self.root.eval(vars) == Some(true)
    }
}

impl Cond {
    fn eval(&self, vars: &Variables) -> Option<bool> {
        match self {
            Self::Or(a, b) => match (a.eval(vars), b.eval(vars)) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            },
            Self::And(a, b) => match (a.eval(vars), b.eval(vars)) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            },
            Self::Not(inner) => inner.eval(vars).map(|value| !value),
            Self::Cmp(op, a, b) => {
                let (a, b) = (a.eval(vars)?, b.eval(vars)?);
                Some(match op {
                    CmpOp::Gt => a > b,
                    CmpOp::Ge => a >= b,
                    CmpOp::Lt => a < b,
                    CmpOp::Le => a <= b,
                    CmpOp::Eq => a == b,
                    CmpOp::Ne => a != b,
                })
            }
        }
    }
}

impl Num {
    fn eval(&self, vars: &Variables) -> Option<f64> {
        match self {
            Self::Literal(value) => Some(*value),
            Self::Var(name) => vars.get(name).copied(),
            Self::Neg(inner) => inner.eval(vars).map(|value| -value),
            Self::Arith(op, a, b) => {
                let (a, b) = (a.eval(vars)?, b.eval(vars)?);
                match op {
                    ArithOp::Add => Some(a + b),
                    ArithOp::Sub => Some(a - b),
                    ArithOp::Mul => Some(a * b),
                    ArithOp::Div => (b != 0.0).then(|| a / b),
                }
            }
        }
    }
}

/// watch ごとに永続化する判定状態
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TriggerState {
    /// 条件が連続で成立している回数
    pub streak: u32,
    /// 今回の異常の開始時刻
    pub since: Option<i64>,
    pub last_fired: Option<i64>,
    /// 発火済みで、まだ回復していない
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Outcome {
    Normal,
    /// 条件は成立しているが連続回数が足りない
    Pending,
    /// クールダウン中で発火を見送った
    Suppressed,
    Fired,
    Recovered,
}

/// 1 回分の判定結果を状態へ反映する。時刻は Unix 秒
pub fn advance(state: &mut TriggerState, matched: bool, trigger: &Trigger, now: i64) -> Outcome {
    if !matched {
        let outcome = if state.active {
            Outcome::Recovered
        } else {
            Outcome::Normal
        };
        state.streak = 0;
        state.since = None;
        state.active = false;
        return outcome;
    }

    state.streak += 1;
    state.since.get_or_insert(now);
    if state.streak < trigger.consecutive {
        return Outcome::Pending;
    }
    let cooldown = trigger.cooldown.as_secs() as i64;
    if state.last_fired.is_some_and(|fired| now - fired < cooldown) {
        return Outcome::Suppressed;
    }
    state.last_fired = Some(now);
    state.active = true;
    Outcome::Fired
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn expr(source: &str) -> Expr {
        Expr::try_from(source.to_string()).unwrap()
    }

    fn vars(pairs: &[(&str, f64)]) -> Variables {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    const EXAMPLE: &str = "loss >= 0.5 || rtt_p50 > baseline.rtt_p95 * 2";

    #[test]
    fn example_condition_fires_on_loss_without_baseline() {
        assert!(expr(EXAMPLE).matches(&vars(&[("loss", 1.0)])));
    }

    #[test]
    fn example_condition_ignores_rtt_until_baseline_exists() {
        let current = vars(&[("loss", 0.0), ("rtt_p50", 500.0)]);
        assert!(!expr(EXAMPLE).matches(&current));
    }

    #[test]
    fn example_condition_fires_on_rtt_with_baseline() {
        let baseline = [("loss", 0.0), ("baseline.rtt_p95", 20.0)];
        let slow = vars(&[baseline[0], baseline[1], ("rtt_p50", 41.0)]);
        let fine = vars(&[baseline[0], baseline[1], ("rtt_p50", 40.0)]);
        assert!(expr(EXAMPLE).matches(&slow));
        assert!(!expr(EXAMPLE).matches(&fine));
    }

    #[test]
    fn unknown_values_never_fire_even_when_negated() {
        assert!(!expr("!(rtt_p50 > 1)").matches(&vars(&[])));
        assert!(!expr("rtt_p50 > 1 && loss > 0").matches(&vars(&[("loss", 1.0)])));
    }

    #[test]
    fn false_and_unknown_is_false_under_negation() {
        assert!(expr("!(rtt_p50 > 1 && loss > 0)").matches(&vars(&[("loss", 0.0)])));
    }

    #[test]
    fn precedence_and_grouping() {
        let v = vars(&[("loss", 2.0), ("value", 3.0)]);
        assert!(expr("loss + value * 2 == 8").matches(&v));
        assert!(expr("(loss + value) * 2 == 10").matches(&v));
        assert!(expr("(loss > 1) && (value > 1)").matches(&v));
        assert!(expr("((loss + 1) > 2)").matches(&v));
        assert!(expr("loss > 9 || loss > 1 && value > 1").matches(&v));
        assert!(expr("-loss < 0").matches(&v));
    }

    #[test]
    fn division_by_zero_is_unknown() {
        assert!(!expr("loss / 0 > 0").matches(&vars(&[("loss", 1.0)])));
    }

    #[test]
    fn rejects_malformed_expressions() {
        for bad in [
            "",
            "loss",
            "loss >",
            "loss >= 0.5 ||",
            "(loss > 1",
            "loss > 1 2",
            "nope > 1",
            "baseline.nope > 1",
            "loss @ 1",
            "1.2.3 > 1",
        ] {
            assert!(Expr::try_from(bad.to_string()).is_err(), "{bad:?}");
        }
    }

    fn trigger(consecutive: u32, cooldown_secs: u64) -> Trigger {
        Trigger {
            when: expr("loss > 0"),
            consecutive,
            cooldown: Duration::from_secs(cooldown_secs),
            recover_notify: true,
        }
    }

    #[test]
    fn fires_after_consecutive_matches() {
        let trigger = trigger(3, 1800);
        let mut state = TriggerState::default();
        assert_eq!(advance(&mut state, true, &trigger, 0), Outcome::Pending);
        assert_eq!(advance(&mut state, true, &trigger, 300), Outcome::Pending);
        assert_eq!(advance(&mut state, true, &trigger, 600), Outcome::Fired);
        assert_eq!(state.since, Some(0));
    }

    #[test]
    fn a_single_good_sample_resets_the_streak() {
        let trigger = trigger(2, 1800);
        let mut state = TriggerState::default();
        advance(&mut state, true, &trigger, 0);
        assert_eq!(advance(&mut state, false, &trigger, 300), Outcome::Normal);
        assert_eq!(advance(&mut state, true, &trigger, 600), Outcome::Pending);
        assert_eq!(state.since, Some(600));
    }

    #[test]
    fn cooldown_suppresses_then_allows_refiring() {
        let trigger = trigger(1, 1800);
        let mut state = TriggerState::default();
        assert_eq!(advance(&mut state, true, &trigger, 0), Outcome::Fired);
        assert_eq!(
            advance(&mut state, true, &trigger, 1799),
            Outcome::Suppressed
        );
        assert_eq!(advance(&mut state, true, &trigger, 1800), Outcome::Fired);
    }

    #[test]
    fn cooldown_survives_recovery() {
        let trigger = trigger(1, 1800);
        let mut state = TriggerState::default();
        advance(&mut state, true, &trigger, 0);
        assert_eq!(
            advance(&mut state, false, &trigger, 300),
            Outcome::Recovered
        );
        assert_eq!(
            advance(&mut state, true, &trigger, 600),
            Outcome::Suppressed
        );
    }

    #[test]
    fn recovery_is_reported_once_and_only_after_firing() {
        let trigger = trigger(2, 1800);
        let mut state = TriggerState::default();
        advance(&mut state, true, &trigger, 0);
        assert_eq!(advance(&mut state, false, &trigger, 300), Outcome::Normal);
        advance(&mut state, true, &trigger, 600);
        advance(&mut state, true, &trigger, 900);
        assert_eq!(
            advance(&mut state, false, &trigger, 1200),
            Outcome::Recovered
        );
        assert_eq!(advance(&mut state, false, &trigger, 1500), Outcome::Normal);
    }
}
