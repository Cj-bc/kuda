use super::{Sample, dns, icmp};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// ICMP が通らないときに `gateway` で試すポート。ルーターで開いていることが多い順
const GATEWAY_PORTS: [u16; 3] = [53, 80, 443];

/// 複数アドレスのホストで、次のアドレスへの接続を追加で始めるまでの間隔。
/// RFC 8305 (Happy Eyeballs) の推奨値
const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// `gateway` で ICMP だけを先に試す時間の上限。この間に応答があればポートには触れない
const ICMP_HEAD_START: Duration = Duration::from_millis(500);

/// ターゲット 1 件に使える時間の期限。DNS 解決や各接続には残り時間だけを渡し、
/// 試行を重ねても全体が timeout を超えないようにする
#[derive(Debug, Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn after(timeout: Duration) -> Self {
        Self(Instant::now() + timeout)
    }

    /// `now` 時点の残り時間。期限を過ぎていれば None
    fn remaining_at(self, now: Instant) -> Option<Duration> {
        self.0
            .checked_duration_since(now)
            .filter(|remaining| !remaining.is_zero())
    }

    fn remaining(self) -> Option<Duration> {
        self.remaining_at(Instant::now())
    }
}

pub fn check(target: &str, gateway: Option<IpAddr>, timeout: Duration) -> Result<Sample, String> {
    let deadline = Deadline::after(timeout);
    if target == "gateway" {
        let ip = gateway.ok_or("no default gateway")?;
        return check_gateway(ip, deadline);
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("target needs a port: {target}"))?;
    let port: u16 = port.parse().map_err(|_| format!("invalid port: {port}"))?;

    let addresses = if host == "gateway" {
        vec![SocketAddr::new(gateway.ok_or("no default gateway")?, port)]
    } else {
        let host = host.trim_matches(['[', ']']);
        let remaining = deadline
            .remaining()
            .ok_or_else(|| format!("timed out resolving {host}"))?;
        dns::resolve(host, port, remaining)?
    };
    if addresses.is_empty() {
        return Err(format!("no addresses for {host}"));
    }

    let attempts = addresses
        .into_iter()
        .enumerate()
        .map(|(index, address)| {
            let delay = if index == 0 {
                Duration::ZERO
            } else {
                CONNECTION_ATTEMPT_DELAY
            };
            // 通常のターゲットでは接続拒否も失敗。次のアドレスをすぐ試す
            Attempt::new(delay, move |remaining| match connect(address, remaining) {
                Ok(rtt_ms) => Reply::Rtt(rtt_ms),
                Err(error) => Reply::Failed(format!("{address}: {error}")),
            })
        })
        .collect();
    race(
        attempts,
        deadline,
        format!("timed out connecting to {host}"),
    )
}

fn connect(address: SocketAddr, timeout: Duration) -> std::io::Result<f64> {
    let started = Instant::now();
    TcpStream::connect_timeout(&address, timeout)?;
    Ok(started.elapsed().as_secs_f64() * 1000.0)
}

/// ポートに依らない ICMP を先に試し、応答が無いときだけ各ポートを同時に試す。
/// Windows は RST 後も SYN を再送し、閉じたポートの拒否が分かるまで 2 秒ほど
/// かかるので、ポートには順番に時間を分けず、どれにも残り時間全体を渡す
fn check_gateway(ip: IpAddr, deadline: Deadline) -> Result<Sample, String> {
    let Some(remaining) = deadline.remaining() else {
        return Err(format!("timed out reaching gateway {ip}"));
    };
    let mut attempts = Vec::new();
    let mut delay = Duration::ZERO;
    // 全ポートをフィルタするゲートウェイもあるので ICMP を優先する
    if let IpAddr::V4(ip) = ip {
        attempts.push(Attempt::icmp(move |remaining| {
            icmp::echo(ip, remaining).map_or(Reply::IcmpFailed, Reply::Rtt)
        }));
        delay = port_delay(remaining);
    }
    for port in GATEWAY_PORTS {
        attempts.push(Attempt::new(delay, move |remaining| {
            match connect(SocketAddr::new(ip, port), remaining) {
                Ok(rtt_ms) => Reply::Rtt(rtt_ms),
                // RST が返るなら到達はできている。ただし Windows は RST 後も SYN を
                // 再送するので、この所要時間は RTT として記録しない
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => Reply::Refused,
                Err(error) => Reply::Failed(format!("{ip}:{port}: {error}")),
            }
        }));
        // 2 番目以降のポートは 1 番目と同時に始める
        delay = Duration::ZERO;
    }
    race(
        attempts,
        deadline,
        format!("timed out reaching gateway {ip}"),
    )
}

/// ICMP を始めてからポートを試し始めるまでの先行時間。ポートの試行に時間を
/// 残すため、残り時間の 1/3 までにする
fn port_delay(remaining: Duration) -> Duration {
    ICMP_HEAD_START.min(remaining / 3)
}

/// 並行に走らせる試行 1 回の結果
#[derive(Debug)]
enum Reply {
    /// ICMP の応答か接続の成功。RTT を記録できる
    Rtt(f64),
    /// RST が返った。到達はできているが RTT は記録しない
    Refused,
    Failed(String),
    IcmpFailed,
}

type Run = Box<dyn FnOnce(Duration) -> Reply + Send>;

/// [`race`] で走らせる試行 1 件
struct Attempt {
    /// 直前の試行を始めてから、この試行を始めるまでの待ち時間。
    /// 動いている試行がすべて終わったら待たずに始める
    delay: Duration,
    icmp: bool,
    /// 残り時間を受け取って試す
    run: Run,
}

impl Attempt {
    fn new(delay: Duration, run: impl FnOnce(Duration) -> Reply + Send + 'static) -> Self {
        Self {
            delay,
            icmp: false,
            run: Box::new(run),
        }
    }

    fn icmp(run: impl FnOnce(Duration) -> Reply + Send + 'static) -> Self {
        Self {
            icmp: true,
            ..Self::new(Duration::ZERO, run)
        }
    }
}

/// 試行を `delay` ずつずらしながら別スレッドで始め、先に始めた試行も期限まで
/// 生かしておく。RTT を測れた最初の結果を返し、RST だけなら ICMP の結果を
/// 待ってから到達可能とする。期限を過ぎたら残りは待たず、新しい試行も始めない
fn race(
    attempts: Vec<Attempt>,
    deadline: Deadline,
    timeout_error: String,
) -> Result<Sample, String> {
    let (sender, receiver) = mpsc::channel();
    let mut waiting = attempts.into_iter().peekable();
    let mut running = 0;
    let mut last_started = Instant::now();
    let mut icmp_pending = false;
    let mut refused = false;
    let mut last_error = None;
    loop {
        if refused && !icmp_pending {
            return Ok(Sample::default());
        }
        let now = Instant::now();
        let Some(remaining) = deadline.remaining_at(now) else {
            break;
        };
        let next_start = waiting.peek().map(|next| last_started + next.delay);
        if let Some(start) = next_start
            && (running == 0 || start <= now)
        {
            let attempt = waiting.next().expect("peeked");
            let sender = sender.clone();
            std::thread::spawn(move || {
                let _ = sender.send((attempt.run)(remaining));
            });
            icmp_pending |= attempt.icmp;
            running += 1;
            last_started = now;
            continue;
        }
        if running == 0 {
            break;
        }

        let wait = next_start.map_or(remaining, |start| {
            start.saturating_duration_since(now).min(remaining)
        });
        // 待ち切ったときは、次の試行を始める時刻か期限が来ている
        let Ok(reply) = receiver.recv_timeout(wait) else {
            continue;
        };
        running -= 1;
        match reply {
            Reply::Rtt(rtt_ms) => return Ok(Sample::rtt(rtt_ms)),
            Reply::Refused => refused = true,
            Reply::Failed(error) => last_error = Some(error),
            Reply::IcmpFailed => icmp_pending = false,
        }
    }
    if refused {
        return Ok(Sample::default());
    }
    if deadline.remaining().is_none() {
        return Err(timeout_error);
    }
    Err(last_error.unwrap_or(timeout_error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn closed_port() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn open_port_reports_rtt() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let sample = check(&target, None, TIMEOUT).unwrap();
        assert!(sample.rtt_ms.is_some());
    }

    #[test]
    fn closed_port_is_a_failure() {
        let target = format!("127.0.0.1:{}", closed_port());
        assert!(check(&target, None, TIMEOUT).is_err());
    }

    #[test]
    fn gateway_with_explicit_port_is_substituted() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let target = format!("gateway:{}", listener.local_addr().unwrap().port());
        let gateway = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(check(&target, gateway, TIMEOUT).is_ok());
        assert!(check(&target, None, TIMEOUT).is_err());
    }

    #[test]
    fn local_gateway_is_reachable() {
        // ICMP が使えない環境でも、閉じたポートの RST で到達可能と判定される
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(check_gateway(ip, Deadline::after(TIMEOUT)).is_ok());
    }

    #[test]
    fn missing_gateway_is_a_failure() {
        assert!(check("gateway", None, TIMEOUT).is_err());
    }

    #[test]
    fn check_ends_within_the_timeout() {
        // 192.0.2.0/24 は文書用のアドレスで応答は返らない。経路が無ければ即座に、
        // あれば期限で失敗する。どちらでも timeout を超えないことだけを見る
        let timeout = Duration::from_millis(300);
        let started = Instant::now();
        assert!(check("192.0.2.1:9", None, timeout).is_err());
        assert!(started.elapsed() < timeout * 2);
    }

    #[test]
    fn expired_check_names_the_host() {
        assert_eq!(
            check("192.0.2.1:9", None, Duration::ZERO),
            Err("timed out resolving 192.0.2.1".to_string())
        );
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            check_gateway(ip, Deadline(Instant::now())),
            Err("timed out reaching gateway 127.0.0.1".to_string())
        );
    }

    #[test]
    fn deadline_shrinks_and_expires() {
        let start = Instant::now();
        let deadline = Deadline(start + TIMEOUT);
        assert_eq!(deadline.remaining_at(start), Some(TIMEOUT));
        assert_eq!(
            deadline.remaining_at(start + Duration::from_secs(2)),
            Some(Duration::from_secs(3))
        );
        assert_eq!(deadline.remaining_at(start + TIMEOUT), None);
        assert_eq!(deadline.remaining_at(start + TIMEOUT * 2), None);
    }

    /// 渡された時間を使い切ってから失敗する、応答しない接続先
    fn silent(delay: Duration, started: Arc<AtomicUsize>) -> Attempt {
        Attempt::new(delay, move |remaining| {
            started.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(remaining);
            Reply::Failed("timed out".to_string())
        })
    }

    /// `after` 経ってから結果を返す接続先
    fn replies_after(delay: Duration, after: Duration, reply: fn() -> Reply) -> Attempt {
        Attempt::new(delay, move |_| {
            std::thread::sleep(after);
            reply()
        })
    }

    #[test]
    fn silent_attempts_stop_at_the_deadline() {
        let timeout = Duration::from_millis(300);
        let started = Arc::new(AtomicUsize::new(0));
        let attempts = (0..5)
            .map(|_| silent(Duration::from_millis(100), started.clone()))
            .collect();
        let begun = Instant::now();
        let result = race(
            attempts,
            Deadline::after(timeout),
            "timed out x".to_string(),
        );
        assert_eq!(result, Err("timed out x".to_string()));
        assert!(begun.elapsed() < timeout * 2);
        // 期限を過ぎてからは新しい試行を始めない
        assert!(started.load(Ordering::SeqCst) <= 3);
    }

    #[test]
    fn slow_first_address_is_not_cut_off() {
        // 先頭のアドレスが遅くても、後続を追加で始めつつ先頭の応答を待ち続ける
        let started = Arc::new(AtomicUsize::new(0));
        let mut attempts = vec![replies_after(
            Duration::ZERO,
            Duration::from_millis(400),
            || Reply::Rtt(400.0),
        )];
        attempts.extend((0..7).map(|_| silent(Duration::from_millis(50), started.clone())));
        let result = race(
            attempts,
            Deadline::after(Duration::from_secs(2)),
            String::new(),
        );
        assert_eq!(result, Ok(Sample::rtt(400.0)));
        assert!(started.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn failed_attempt_starts_the_next_at_once() {
        let attempts = vec![
            replies_after(Duration::ZERO, Duration::ZERO, || {
                Reply::Failed("refused".to_string())
            }),
            replies_after(TIMEOUT, Duration::ZERO, || Reply::Rtt(1.0)),
        ];
        let begun = Instant::now();
        let result = race(attempts, Deadline::after(TIMEOUT * 2), String::new());
        assert_eq!(result, Ok(Sample::rtt(1.0)));
        assert!(begun.elapsed() < TIMEOUT);
    }

    #[test]
    fn all_failures_report_the_last_error() {
        // 同時に始まる試行の順序を固定するため、"b" を遅らせる
        let attempts = vec![
            replies_after(Duration::ZERO, Duration::ZERO, || {
                Reply::Failed("a".to_string())
            }),
            replies_after(Duration::ZERO, Duration::from_millis(100), || {
                Reply::Failed("b".to_string())
            }),
        ];
        let result = race(attempts, Deadline::after(TIMEOUT), String::new());
        assert_eq!(result, Err("b".to_string()));
    }

    #[test]
    fn expired_deadline_starts_no_attempt() {
        let started = Arc::new(AtomicUsize::new(0));
        let attempts = vec![silent(Duration::ZERO, started.clone())];
        let result = race(attempts, Deadline(Instant::now()), "timed out".to_string());
        assert_eq!(result, Err("timed out".to_string()));
        assert_eq!(started.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn icmp_reply_within_head_start_leaves_ports_untouched() {
        let started = Arc::new(AtomicUsize::new(0));
        let attempts = vec![
            Attempt::icmp(|_| {
                std::thread::sleep(Duration::from_millis(20));
                Reply::Rtt(20.0)
            }),
            silent(Duration::from_millis(500), started.clone()),
            silent(Duration::ZERO, started.clone()),
        ];
        let result = race(attempts, Deadline::after(TIMEOUT), String::new());
        assert_eq!(result, Ok(Sample::rtt(20.0)));
        assert_eq!(started.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn rtt_after_refusal_wins_while_icmp_is_pending() {
        // ICMP の結果を待つ間に別ポートの接続が成功すれば、その RTT を採る
        let attempts = vec![
            Attempt::icmp(|remaining| {
                std::thread::sleep(remaining);
                Reply::IcmpFailed
            }),
            replies_after(Duration::ZERO, Duration::ZERO, || Reply::Refused),
            replies_after(Duration::ZERO, Duration::from_millis(100), || {
                Reply::Rtt(3.0)
            }),
        ];
        let result = race(attempts, Deadline::after(TIMEOUT), String::new());
        assert_eq!(result, Ok(Sample::rtt(3.0)));
    }

    #[test]
    fn refusal_counts_once_icmp_failed() {
        let attempts = vec![
            Attempt::icmp(|_| Reply::IcmpFailed),
            replies_after(Duration::ZERO, Duration::from_millis(50), || Reply::Refused),
            silent(Duration::ZERO, Arc::new(AtomicUsize::new(0))),
        ];
        let begun = Instant::now();
        let result = race(attempts, Deadline::after(TIMEOUT), String::new());
        assert_eq!(result, Ok(Sample::default()));
        assert!(begun.elapsed() < TIMEOUT);
    }

    #[test]
    fn icmp_head_start_leaves_time_for_windows_refusals() {
        // 既定の timeout 3 秒でも、ポートには RST の検出に要る 2 秒以上が残る
        let timeout = Duration::from_secs(3);
        assert!(timeout - port_delay(timeout) >= Duration::from_secs(2));
        // 短い timeout でもポートに 2/3 は残る
        let short = Duration::from_millis(600);
        assert_eq!(port_delay(short), Duration::from_millis(200));
        assert_eq!(port_delay(Duration::from_secs(60)), ICMP_HEAD_START);
    }
}
