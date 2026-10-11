//! Chinese sentences for the error codes the daemon returns.
//!
//! The daemon's JSON body keeps the machine code and its English `message`.
//! What a person reads is the sentence in [`explain`]. The English text is
//! appended as 「（详情：…）」 only when it says something the sentence does
//! not already say. An unknown code keeps both the code and the HTTP status,
//! so a new daemon code is visible instead of being silently reworded.
//!
//! [`tests::every_daemon_error_code_has_a_chinese_sentence`] scans the daemon
//! sources for `error_response(` literals. Adding a code there without a row
//! here fails that test.

use std::fmt;

/// One mapped code: the Chinese sentence, and the daemon's stock English
/// message. When the daemon returns exactly that English text, repeating it
/// adds nothing and the detail is omitted.
struct Row {
    code: &'static str,
    zh: &'static str,
    /// The message the daemon sends with this code. `None` when the message
    /// is built per request (it always carries detail worth showing).
    en: Option<&'static str>,
}

/// Every `error.code` the daemon emits, in one table.
///
/// Collected from `error_response(` literals and the `"code":` literals in
/// `crates/aw-daemon/src`. A code the daemon uses for more than one message
/// has `en: None`, so whichever message arrived is shown as the detail.
const ROWS: &[Row] = &[
    Row {
        code: "not_found",
        zh: "找不到这个会话（或它不属于你）",
        en: None,
    },
    Row {
        code: "no_sessions",
        zh: "还没有你的会话，@last 无处可指",
        en: Some("this account has no sessions"),
    },
    Row {
        code: "session_not_found",
        zh: "找不到这个会话（或它不属于你）",
        en: Some("session not found"),
    },
    Row {
        code: "finding_not_found",
        zh: "找不到这条发现",
        en: Some("finding not found"),
    },
    Row {
        code: "forbidden",
        zh: "不能接管其他用户的进程，需要管理员权限",
        en: None,
    },
    Row {
        code: "owner_action_forbidden",
        zh: "只有会话主人能操作",
        en: Some("only the session owner may operate it"),
    },
    Row {
        code: "not_your_process",
        zh: "不能接管其他用户的进程，需要管理员权限",
        // The daemon sends one of two messages with this code (attach names the
        // administrator requirement, adopt does not), so either one is a detail.
        en: Some("this process belongs to another account"),
    },
    Row {
        code: "unauthorized",
        zh: "没有通过后台的身份验证",
        en: None,
    },
    Row {
        code: "program_not_found",
        zh: "找不到这个程序或工作目录",
        en: Some("the program or the working directory was not found"),
    },
    Row {
        code: "program_not_permitted",
        zh: "没有权限运行这个程序或进入工作目录",
        en: Some("the program or the working directory is not accessible to this account"),
    },
    Row {
        code: "collector_unavailable",
        zh: "本版本只在 Linux 上能记录进程，请用 --no-daemon",
        en: Some("the poll sampler reads process identity only on Linux in this build"),
    },
    Row {
        code: "adopt_timeout",
        zh: "接管超时，会话已关闭",
        en: Some("adopt arrived after the timeout; the session was closed"),
    },
    Row {
        code: "caller_unidentified",
        zh: "无法识别调用者的账户",
        en: Some("the caller's account could not be identified"),
    },
    Row {
        code: "unidentified_peer",
        zh: "后台认不出你是哪个用户，已拒绝这次请求。请确认 `aw` 和后台是同一个版本，还不行就重启后台。",
        en: Some("pipe client could not be identified"),
    },
    Row {
        code: "caller_groups_unknown",
        zh: "读不到调用者账户的用户组，不能以你的身份启动程序",
        en: None,
    },
    Row {
        code: "launch_identity_unsupported",
        zh: "这个平台上后台不能以你的身份启动程序，请用 aw run",
        en: None,
    },
    Row {
        code: "caller_unknown",
        zh: "调用者的账户在用户库中没有记录",
        en: Some("the caller's account has no entry in the user database"),
    },
    Row {
        code: "launch_other_user",
        zh: "后台以普通账户运行，不能为其他账户启动程序",
        en: Some(
            "the service runs under an ordinary account and cannot start programs for another account",
        ),
    },
    Row {
        code: "drop_failed",
        zh: "程序没能切换到调用者的账户，已被停止",
        en: Some("the program did not switch to the caller's account and was stopped"),
    },
    Row {
        code: "store_unavailable",
        zh: "后台没有打开会话数据库，无法记录",
        en: Some("recording needs the session database; this daemon has none open"),
    },
    Row {
        code: "no_database",
        zh: "后台没有数据库，无法记录会话",
        en: Some("this daemon has no database to record sessions in"),
    },
    Row {
        code: "bad_argument",
        zh: "请求参数不正确",
        en: None,
    },
    Row {
        code: "bad_request",
        zh: "请求内容不正确",
        en: None,
    },
    Row {
        code: "invalid_config_key",
        zh: "配置键不存在或不受支持",
        en: None,
    },
    Row {
        code: "invalid_config",
        zh: "配置键或配置值无效",
        en: None,
    },
    Row {
        code: "config_path_unavailable",
        zh: "后台没有可写的配置文件",
        en: Some("后台没有可写的配置文件"),
    },
    Row {
        code: "config_write_failed",
        zh: "无法写入配置文件",
        en: None,
    },
    Row {
        code: "bad_query",
        zh: "查询参数不正确",
        en: None,
    },
    Row {
        code: "bad_filter",
        zh: "过滤条件不正确",
        en: None,
    },
    Row {
        code: "confirm_required",
        zh: "删除会话需要确认：先用 dry_run=true 查看，再传 confirm=true 删除",
        en: Some(
            "purge deletes sessions: send dry_run=true to list them, then confirm=true to delete",
        ),
    },
    Row {
        code: "not_json",
        zh: "请求体不是 JSON",
        en: Some("hook body is not JSON"),
    },
    Row {
        code: "random_unavailable",
        zh: "系统的随机数源不可用，没有签发票据或令牌",
        en: None,
    },
    Row {
        code: "store",
        zh: "读写会话数据库失败",
        en: None,
    },
    Row {
        code: "db_busy",
        zh: "会话数据库正忙",
        en: Some("The session database is busy (the service is writing)."),
    },
    Row {
        code: "export",
        zh: "导出会话失败",
        en: None,
    },
    Row {
        code: "payload_too_large",
        zh: "请求体超过 64 KiB",
        en: Some("request body exceeds 64 KiB"),
    },
    Row {
        code: "method_not_allowed",
        zh: "不支持这个请求方法",
        en: Some("method not allowed"),
    },
    Row {
        code: "no_log_file",
        zh: "这个后台没有写日志文件",
        en: Some("this daemon writes no log file"),
    },
    Row {
        code: "log_unreadable",
        zh: "读不到后台的日志文件",
        en: None,
    },
    Row {
        code: "internal",
        zh: "后台内部出错",
        en: None,
    },
    Row {
        code: "no_such_process",
        zh: "这个进程不在运行，或读不到它的身份",
        en: Some("pid is not running (or its identity cannot be read)"),
    },
    Row {
        code: "spawn_failed",
        zh: "程序没能启动",
        en: Some("the program could not be started"),
    },
    Row {
        code: "session_ended",
        zh: "这个会话已经结束，不能再接管",
        en: Some("session is not open for attach"),
    },
    Row {
        code: "misdirected",
        zh: "请求的主机不是本机的后台监听地址",
        en: Some("host is not the loopback listener"),
    },
    Row {
        code: "dev_proxy",
        zh: "界面开发服务器不可用",
        en: None,
    },
    Row {
        code: "ambiguous",
        zh: "这个名字对应多个会话",
        en: None,
    },
];

/// The Chinese sentence for `code`, when this table has one.
#[cfg(test)]
#[must_use]
pub(crate) fn explain(code: &str) -> Option<&'static str> {
    ROWS.iter().find(|row| row.code == code).map(|row| row.zh)
}

/// Write one daemon HTTP failure the way a person should read it.
///
/// A known code becomes its Chinese sentence. The daemon's English message
/// follows as 「（详情：…）」 unless it is the stock wording for that code,
/// in which case it adds nothing. An unknown code keeps the code, the status,
/// and the message: 「后台返回错误 {code}（HTTP {status}）：{message}」.
pub(crate) fn write_status(
    f: &mut fmt::Formatter<'_>,
    status: u16,
    code: Option<&str>,
    message: &str,
) -> fmt::Result {
    let Some(code) = code.filter(|code| !code.is_empty()) else {
        return write!(f, "后台返回 HTTP {status}：{message}");
    };
    if code == "db_busy" {
        let waited = busy_waited_seconds(message).unwrap_or(0);
        return write!(
            f,
            "会话数据库正忙（后台在写入），等了 {waited} 秒还是没轮到，请稍后再试。"
        );
    }
    let Some(row) = ROWS.iter().find(|row| row.code == code) else {
        return write!(f, "后台返回错误 {code}（HTTP {status}）：{message}");
    };
    f.write_str(row.zh)?;
    if detail_adds(row.en, message) {
        write!(f, "（详情：{message}）")?;
    }
    Ok(())
}

fn busy_waited_seconds(message: &str) -> Option<u64> {
    let marker = "Waited ";
    let rest = message.split_once(marker)?.1;
    let digits = rest.split_whitespace().next()?;
    digits.parse().ok()
}

/// Whether `message` says something the mapped sentence does not.
fn detail_adds(stock: Option<&str>, message: &str) -> bool {
    let message = message.trim();
    if message.is_empty() {
        return false;
    }
    // The stock text may be the shared opening of several daemon messages for
    // one code; a message that starts with it adds nothing to the sentence.
    !matches!(stock, Some(stock) if message
        .get(..stock.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(stock)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fmt;

    use super::{explain, write_status, ROWS};

    /// Daemon sources, relative to this crate. A code that appears as the
    /// second argument of `error_response(` in any of them must have a row.
    const DAEMON_SOURCES: &[(&str, &str)] = &[
        (
            "api/routes.rs",
            include_str!("../../aw-daemon/src/api/routes.rs"),
        ),
        (
            "api/watch_routes.rs",
            include_str!("../../aw-daemon/src/api/watch_routes.rs"),
        ),
        (
            "api/launch_as.rs",
            include_str!("../../aw-daemon/src/api/launch_as.rs"),
        ),
        (
            "api/control.rs",
            include_str!("../../aw-daemon/src/api/control.rs"),
        ),
        ("api/ipc.rs", include_str!("../../aw-daemon/src/api/ipc.rs")),
        (
            "api/system_procs.rs",
            include_str!("../../aw-daemon/src/api/system_procs.rs"),
        ),
        (
            "api/auth.rs",
            include_str!("../../aw-daemon/src/api/auth.rs"),
        ),
        (
            "api/http.rs",
            include_str!("../../aw-daemon/src/api/http.rs"),
        ),
        (
            "api/http_events.rs",
            include_str!("../../aw-daemon/src/api/http_events.rs"),
        ),
        (
            "api/findings.rs",
            include_str!("../../aw-daemon/src/api/findings.rs"),
        ),
        (
            "api/agent.rs",
            include_str!("../../aw-daemon/src/api/agent.rs"),
        ),
        (
            "export/data.rs",
            include_str!("../../aw-daemon/src/export/data.rs"),
        ),
        (
            "export/markdown.rs",
            include_str!("../../aw-daemon/src/export/markdown.rs"),
        ),
    ];

    fn render(status: u16, code: Option<&str>, message: &str) -> String {
        struct Shown(u16, Option<String>, String);
        impl fmt::Display for Shown {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_status(f, self.0, self.1.as_deref(), &self.2)
            }
        }
        Shown(status, code.map(str::to_owned), message.to_owned()).to_string()
    }

    #[test]
    fn codes_are_unique() {
        let mut seen: Vec<&str> = ROWS.iter().map(|row| row.code).collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), before, "duplicate code in the table");
    }

    #[test]
    fn known_403_is_the_other_user_sentence() {
        let daemon = "this process belongs to another account; recording another account's process needs an administrator";
        let text = render(403, Some("not_your_process"), daemon);
        assert_eq!(text, "不能接管其他用户的进程，需要管理员权限");
        let adopt = render(
            403,
            Some("not_your_process"),
            "this process belongs to another account and cannot be adopted",
        );
        assert_eq!(adopt, "不能接管其他用户的进程，需要管理员权限", "{adopt}");
        // The same situation under the daemon's other code reads the same way,
        // and a message that adds something is kept as the detail.
        let other = render(403, Some("forbidden"), "administrator required");
        assert!(
            other.starts_with("不能接管其他用户的进程，需要管理员权限"),
            "{other}"
        );
        assert!(
            other.contains("（详情：administrator required）"),
            "{other}"
        );
    }

    #[test]
    fn known_404_names_the_session_and_keeps_the_english_reason() {
        let text = render(404, Some("not_found"), "session not found");
        assert_eq!(
            text,
            "找不到这个会话（或它不属于你）（详情：session not found）"
        );
        assert_eq!(
            render(404, Some("no_sessions"), "this account has no sessions"),
            "还没有你的会话，@last 无处可指"
        );
    }

    #[test]
    fn unknown_code_keeps_the_code_status_and_message() {
        let text = render(418, Some("teapot"), "short and stout");
        assert_eq!(text, "后台返回错误 teapot（HTTP 418）：short and stout");
    }

    #[test]
    fn status_without_a_code_keeps_the_plain_form() {
        assert_eq!(
            render(404, None, "session not found"),
            "后台返回 HTTP 404：session not found"
        );
    }

    #[test]
    fn database_busy_uses_the_measured_wait_in_the_fixed_chinese_sentence() {
        assert_eq!(
            render(
                503,
                Some("db_busy"),
                "The session database is busy (the service is writing). Waited 8 s and still couldn't get in; try again later."
            ),
            "会话数据库正忙（后台在写入），等了 8 秒还是没轮到，请稍后再试。"
        );
    }

    #[test]
    fn every_daemon_error_code_has_a_chinese_sentence() {
        let mut missing: Vec<String> = Vec::new();
        for (name, source) in DAEMON_SOURCES {
            for code in error_response_codes(source) {
                if explain(code).is_none() {
                    missing.push(format!("{name}: {code}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "daemon error codes without a Chinese sentence: {missing:?}"
        );
    }

    /// Second-argument string literals of `error_response(` calls.
    ///
    /// Walks source text. A call whose code argument is not a string literal
    /// (the `error_response` function's own parameter, or `&code`) is skipped:
    /// the literal that feeds it is counted at the call site that has one.
    fn error_response_codes(source: &str) -> Vec<&str> {
        let mut codes = Vec::new();
        let bytes = source.as_bytes();
        let mut from = 0;
        let needle = "error_response(";
        while let Some(at) = source[from..].find(needle) {
            let args_at = from + at + needle.len();
            let Some(end) = matching_paren(bytes, args_at) else {
                break;
            };
            if let Some(code) = nth_string_literal(&source[args_at..end], 1) {
                codes.push(code);
            }
            from = end + 1;
        }
        codes
    }

    /// Index of the `)` matching the `(` just before `open`, inside `bytes`.
    fn matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
        let mut depth = 1i32;
        let mut i = open;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    /// The `"..."` literal that is argument number `n` (0-based) of `args`.
    ///
    /// `None` when that argument is not itself a string literal — a format
    /// expression or a variable, whose code is a literal at the call that
    /// builds it.
    fn nth_string_literal(args: &str, n: usize) -> Option<&str> {
        let bytes = args.as_bytes();
        let mut arg = 0usize;
        let mut i = 0;
        let mut depth = 0i32;
        while i < bytes.len() {
            match bytes[i] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b',' if depth == 0 => arg += 1,
                b'"' if depth == 0 && arg == n => {
                    let start = i + 1;
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        if bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    return Some(&args[start..i]);
                }
                _ => {}
            }
            i += 1;
        }
        None
    }
}
