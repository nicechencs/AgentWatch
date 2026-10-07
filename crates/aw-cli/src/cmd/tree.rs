//! Command tree for `aw`, matching api-and-cli section 2.
//!
//! Flags are declared so `--help` lists them. This card does not act on them.
//! `--name` on `attach` is the process pattern from the usage synopsis. The
//! same flag is also described there as the session name ("same as run"); one
//! flag cannot be both, so the session name is left for P1-CLI-02.

#![allow(dead_code)]

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aw",
    version,
    about = "AgentWatch 命令行客户端",
    subcommand_required = true,
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    /// 机器可读的 JSON 输出
    #[arg(long, global = true)]
    pub(crate) json: bool,
    /// Unix socket 或 Windows 命名管道
    #[arg(long, global = true)]
    pub(crate) socket: Option<String>,
    /// 改用回环 HTTP。只接受 http://127.0.0.1:<port> 或 http://localhost:<port>
    #[arg(long, global = true)]
    pub(crate) http: Option<String>,
    /// HTTP Bearer 令牌，也可用环境变量 AW_TOKEN。不会写入日志
    #[arg(long, global = true)]
    pub(crate) token: Option<String>,
    /// 语言：zh 或 en
    #[arg(long, global = true, value_parser = ["zh", "en"])]
    pub(crate) lang: Option<String>,
    /// 安静模式
    #[arg(short, long, global = true)]
    pub(crate) quiet: bool,
    /// 更详细的日志，可重复
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// 启动模式
    Run {
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        proxy: bool,
        #[arg(long)]
        proxy_on_reject: Option<String>,
        #[arg(long)]
        no_follow_children: bool,
        #[arg(long)]
        include_proc: Vec<String>,
        #[arg(long)]
        self_report: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long = "env")]
        env_vars: Vec<String>,
        #[arg(long)]
        summary: Option<String>,
        #[arg(long)]
        pin: bool,
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        mcp_tap: bool,
        #[arg(long)]
        no_daemon: bool,
        #[arg(long)]
        raw: Option<String>,
        #[arg(long)]
        unsafe_no_redact: bool,
        /// 目标命令
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// 附着到已有进程
    Attach {
        #[arg(long)]
        pid: Option<u32>,
        /// 进程名 pattern
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        no_follow_children: bool,
        #[arg(long)]
        no_existing_children: bool,
        #[arg(long)]
        move_to_cgroup: bool,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        pin: bool,
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        until_exit: bool,
        #[arg(long)]
        duration: Option<String>,
    },
    /// 停止监控，不结束进程
    Stop { session: String },
    /// 列出可附着的进程
    Ps {
        #[arg(long)]
        agents_only: bool,
        #[arg(long)]
        filter: Option<String>,
    },
    /// 会话
    #[command(subcommand)]
    Sessions(SessionsCmd),
    /// 时间线
    Timeline {
        session: String,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        follow: bool,
        #[arg(long)]
        limit: Option<u64>,
    },
    /// 进程
    Procs {
        session: String,
        #[arg(long)]
        tree: bool,
        #[arg(long)]
        filter: Option<String>,
    },
    /// 文件访问
    Files {
        session: String,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        group_by: Option<String>,
        #[arg(long)]
        sort: Option<String>,
    },
    /// 网络流
    Flows {
        session: String,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        group_by: Option<String>,
        #[arg(long)]
        sort: Option<String>,
    },
    /// HTTP 记录
    Http {
        session: String,
        #[arg(long)]
        filter: Option<String>,
    },
    /// 发现
    Findings {
        session: String,
        #[arg(long)]
        min_severity: Option<String>,
        #[arg(long)]
        evidence: Option<String>,
    },
    /// 采集缺口
    Gaps { session: String },
    /// 查看某条记录前后的事件
    Around {
        session: String,
        reference: String,
        #[arg(long)]
        window: Option<String>,
    },
    /// 跨会话搜索
    Search {
        text: String,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        kind: Option<String>,
    },
    /// 导出
    Export {
        session: String,
        #[arg(long)]
        format: Option<String>,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        include: Option<String>,
        #[arg(long)]
        redact_paths: bool,
        #[arg(long)]
        redact_hosts: bool,
    },
    /// 打开本地 Web UI
    Ui {
        #[arg(long)]
        no_open: bool,
        #[arg(long)]
        port: Option<u16>,
    },
    /// 自检
    Doctor {
        #[arg(long)]
        perf: bool,
    },
    /// 管理 daemon
    #[command(subcommand)]
    Daemon(DaemonCmd),
    /// 配置
    #[command(subcommand)]
    Config(ConfigCmd),
    /// 代理 CA
    #[command(subcommand)]
    Proxy(ProxyCmd),
    /// 数据库
    #[command(subcommand)]
    Db(DbCmd),
    /// 开发用夹具
    #[command(subcommand)]
    Fixtures(FixturesCmd),
    /// 监控组
    #[command(subcommand)]
    Group(GroupCmd),
    /// Agent 实例
    Agents {
        session: Option<String>,
        #[arg(long)]
        group: Option<String>,
    },
    /// Agent 间链路
    Links {
        session: Option<String>,
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        min_evidence: Option<String>,
    },
    /// MCP 或 A2A 调用
    Rpc {
        session: String,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        target: Option<String>,
    },
    /// 委托链路
    Chain { session: String, reference: String },
    /// 跨主机离线合并
    Merge {
        a: String,
        b: String,
        #[arg(short, long)]
        output: Option<String>,
    },
    /// 接收 Agent hook 事件
    Hook {
        agent: String,
        #[arg(long)]
        session: Option<String>,
    },
    /// stdio 透明包装器
    McpTap {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// 单进程模式
    Dev {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// 版本
    Version {
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum SessionsCmd {
    /// 列出会话
    List {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        active: bool,
        #[arg(long)]
        limit: Option<u64>,
    },
    /// 会话概览
    Show { session: String },
    /// 重命名会话
    Rename { session: String, name: String },
    /// 固定会话，不参与自动清理
    Pin { session: String },
    /// 取消固定
    Unpin { session: String },
    /// 删除会话
    Delete {
        #[arg(required = true)]
        sessions: Vec<String>,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum DaemonCmd {
    /// 状态
    Status,
    /// 启动
    Start,
    /// 停止
    Stop,
    /// 重启
    Restart,
    /// 安装系统服务
    Install,
    /// 卸载系统服务
    Uninstall {
        #[arg(long)]
        purge: bool,
        #[arg(long)]
        check: bool,
    },
    /// 日志
    Logs {
        #[arg(long)]
        follow: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum RulesCmd {
    /// 已加载的规则
    List,
    /// 用夹具试跑一条规则
    Test { rule: String, fixture: String },
}

#[derive(Subcommand)]
pub(crate) enum ConfigCmd {
    /// 显示配置
    Show {
        #[arg(long)]
        effective: bool,
    },
    /// 读取一个键
    Get { key: String },
    /// 设置一个键
    Set {
        key: String,
        #[arg(allow_hyphen_values = true)]
        value: String,
    },
    /// 编辑配置
    Edit,
    /// 输出配置 JSON Schema
    Schema,
    /// 规则
    #[command(subcommand)]
    Rules(RulesCmd),
}

#[derive(Subcommand)]
pub(crate) enum ProxyCmd {
    /// 指纹与创建、到期时间
    CaInfo,
    /// 轮换 CA
    RotateCa {
        #[arg(long)]
        revoke_now: bool,
    },
    /// 安装到用户证书库（高风险，需用户显式执行）
    Trust {
        #[arg(long)]
        user: bool,
    },
    /// 从用户证书库移除
    Untrust,
}

#[derive(Subcommand)]
pub(crate) enum DbCmd {
    /// 体积与各表行数
    Stats,
    /// 压缩数据库
    Vacuum,
    /// 迁移
    Migrate {
        #[arg(long)]
        dry_run: bool,
    },
    /// 清理
    Purge {
        #[arg(long)]
        older_than: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum FixturesCmd {
    /// 录制会话
    Record {
        session: String,
        #[arg(short, long)]
        output: Option<String>,
    },
    /// 离线回放
    Replay {
        file: String,
        #[arg(long)]
        expect: Option<String>,
    },
    /// 替换用户名、主机名和 IP
    Scrub { file: String },
    /// 升级到当前 schema
    Upgrade { file: String },
}

#[derive(Subcommand)]
pub(crate) enum GroupCmd {
    /// 创建监控组
    Create { name: String },
    /// 列出监控组
    List,
    /// 监控组详情
    Show { name: String },
    /// 删除监控组，不删除会话
    Delete { name: String },
    /// Agent 通信图
    Graph {
        name: String,
        #[arg(long)]
        format: Option<String>,
    },
}

/// Stable name of a parsed command, used when reporting that it is not implemented.
#[must_use]
pub(crate) fn command_label(command: &Command) -> &'static str {
    match command {
        Command::Run { .. } => "run",
        Command::Attach { .. } => "attach",
        Command::Stop { .. } => "stop",
        Command::Ps { .. } => "ps",
        Command::Sessions(cmd) => match cmd {
            SessionsCmd::List { .. } => "sessions list",
            SessionsCmd::Show { .. } => "sessions show",
            SessionsCmd::Rename { .. } => "sessions rename",
            SessionsCmd::Pin { .. } => "sessions pin",
            SessionsCmd::Unpin { .. } => "sessions unpin",
            SessionsCmd::Delete { .. } => "sessions delete",
        },
        Command::Timeline { .. } => "timeline",
        Command::Procs { .. } => "procs",
        Command::Files { .. } => "files",
        Command::Flows { .. } => "flows",
        Command::Http { .. } => "http",
        Command::Findings { .. } => "findings",
        Command::Gaps { .. } => "gaps",
        Command::Around { .. } => "around",
        Command::Search { .. } => "search",
        Command::Export { .. } => "export",
        Command::Ui { .. } => "ui",
        Command::Doctor { .. } => "doctor",
        Command::Daemon(cmd) => match cmd {
            DaemonCmd::Status => "daemon status",
            DaemonCmd::Start => "daemon start",
            DaemonCmd::Stop => "daemon stop",
            DaemonCmd::Restart => "daemon restart",
            DaemonCmd::Install => "daemon install",
            DaemonCmd::Uninstall { .. } => "daemon uninstall",
            DaemonCmd::Logs { .. } => "daemon logs",
        },
        Command::Config(cmd) => match cmd {
            ConfigCmd::Show { .. } => "config show",
            ConfigCmd::Get { .. } => "config get",
            ConfigCmd::Set { .. } => "config set",
            ConfigCmd::Edit => "config edit",
            ConfigCmd::Schema => "config schema",
            ConfigCmd::Rules(rules) => match rules {
                RulesCmd::List => "config rules list",
                RulesCmd::Test { .. } => "config rules test",
            },
        },
        Command::Proxy(cmd) => match cmd {
            ProxyCmd::CaInfo => "proxy ca-info",
            ProxyCmd::RotateCa { .. } => "proxy rotate-ca",
            ProxyCmd::Trust { .. } => "proxy trust",
            ProxyCmd::Untrust => "proxy untrust",
        },
        Command::Db(cmd) => match cmd {
            DbCmd::Stats => "db stats",
            DbCmd::Vacuum => "db vacuum",
            DbCmd::Migrate { .. } => "db migrate",
            DbCmd::Purge { .. } => "db purge",
        },
        Command::Fixtures(cmd) => match cmd {
            FixturesCmd::Record { .. } => "fixtures record",
            FixturesCmd::Replay { .. } => "fixtures replay",
            FixturesCmd::Scrub { .. } => "fixtures scrub",
            FixturesCmd::Upgrade { .. } => "fixtures upgrade",
        },
        Command::Group(cmd) => match cmd {
            GroupCmd::Create { .. } => "group create",
            GroupCmd::List => "group list",
            GroupCmd::Show { .. } => "group show",
            GroupCmd::Delete { .. } => "group delete",
            GroupCmd::Graph { .. } => "group graph",
        },
        Command::Agents { .. } => "agents",
        Command::Links { .. } => "links",
        Command::Rpc { .. } => "rpc",
        Command::Chain { .. } => "chain",
        Command::Merge { .. } => "merge",
        Command::Hook { .. } => "hook",
        Command::McpTap { .. } => "mcp-tap",
        Command::Dev { .. } => "dev",
        Command::Version { .. } => "version",
    }
}
