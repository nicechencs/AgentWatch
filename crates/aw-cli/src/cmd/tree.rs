//! Command tree for `aw`, matching api-and-cli section 2.
//!
//! Flags are declared so `--help` lists them. This card does not act on them.
//! `--name` on `attach` is the process pattern from the usage synopsis. The
//! same flag is also described there as the session name ("same as run"); one
//! flag cannot be both, so the session name is left for P1-CLI-02.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aw",
    version,
    about = "AgentWatch 命令行客户端",
    subcommand_required = true,
    disable_help_subcommand = true,
    disable_help_flag = true,
    help_template = "{about-with-newline}\n用法: {usage}\n\n命令：\n{subcommands}\n\n选项：\n{options}\n"
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
    #[arg(long, global = true, value_parser = ["zh", "en"], hide_possible_values = true)]
    pub(crate) lang: Option<String>,
    /// 安静模式
    #[arg(short, long, global = true)]
    pub(crate) quiet: bool,
    /// 更详细的日志，可重复
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,
    /// 显示帮助
    #[arg(short = 'h', long, global = true, action = clap::ArgAction::Help, required = false)]
    pub(crate) help: Option<bool>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// 启动程序并记录
    Run {
        #[arg(long, help = "智能体类型")]
        agent: Option<String>,
        #[arg(long, help = "会话名称")]
        name: Option<String>,
        #[arg(long, help = "注入显式代理（本版本未接入）")]
        proxy: bool,
        #[arg(long, help = "代理被拒绝时的处理方式（本版本未接入）")]
        proxy_on_reject: Option<String>,
        #[arg(long, help = "不跟随子进程")]
        no_follow_children: bool,
        #[arg(long, help = "纳入额外进程（本版本未接入）")]
        include_proc: Vec<String>,
        #[arg(long, help = "智能体自报告来源（本版本未接入）")]
        self_report: Option<String>,
        #[arg(long, help = "被启动程序的工作目录")]
        cwd: Option<String>,
        #[arg(long = "env", help = "只交给被启动的程序，不发给后台")]
        env_vars: Vec<String>,
        #[arg(long, help = "结束时摘要：none、short 或 full")]
        summary: Option<String>,
        #[arg(long, help = "固定会话，不参与自动清理")]
        pin: bool,
        #[arg(long, help = "监控组（本版本未接入）")]
        group: Option<String>,
        #[arg(long, help = "MCP 调用记录（本版本未接入）")]
        mcp_tap: bool,
        #[arg(
            long,
            help = "不经过后台，直接运行程序，不做记录；`aw` 一退出，程序和它启动的子程序都会跟着结束。"
        )]
        no_daemon: bool,
        #[arg(long, help = "原始事件文件（本版本未接入）")]
        raw: Option<String>,
        #[arg(long, help = "关闭脱敏（本版本未接入）")]
        unsafe_no_redact: bool,
        /// 要启动的程序及其参数
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// 附着到已有进程
    Attach {
        #[arg(long, help = "要附着的进程号")]
        pid: Option<u32>,
        /// 进程名 pattern
        #[arg(long, help = "不跟随子进程")]
        name: Option<String>,
        #[arg(long, help = "不纳入已有子进程")]
        no_follow_children: bool,
        #[arg(long, help = "移入 cgroup")]
        no_existing_children: bool,
        #[arg(long, help = "智能体类型")]
        move_to_cgroup: bool,
        #[arg(long, help = "固定会话，不参与自动清理")]
        agent: Option<String>,
        #[arg(long, help = "监控组（本版本未接入）")]
        pin: bool,
        #[arg(long, help = "直到目标进程退出")]
        group: Option<String>,
        #[arg(long, help = "记录时长，例如 10m")]
        until_exit: bool,
        #[arg(long)]
        duration: Option<String>,
    },
    /// 停止记录（程序继续运行）
    Stop {
        /// 会话号或 @last
        session: String,
        /// 管理员操作其他用户会话时，明确指定会话主人
        #[arg(long)]
        owner: Option<String>,
    },
    /// 列出可附着的进程
    Ps {
        #[arg(long)]
        agents_only: bool,
        #[arg(long)]
        filter: Option<String>,
    },
    /// 查看和管理会话
    #[command(subcommand)]
    Sessions(SessionsCmd),
    /// 查看会话时间线
    Timeline {
        /// 会话号或 @last
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
    /// 会话里的进程（含退出码）
    Procs {
        /// 会话号或 @last
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
    /// 会话里的网络流
    Flows {
        /// 会话号或 @last
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
    /// 查看发现
    Findings {
        /// 会话号或 @last
        session: String,
        #[arg(long, value_parser = ["info", "notice", "warn"])]
        min_severity: Option<String>,
        /// 证据等级列表：E1、I 或 content_match，逗号分隔
        #[arg(long)]
        evidence: Option<String>,
        /// 覆盖全局 --lang。zh 或 en
        #[arg(long, value_parser = ["zh", "en"])]
        lang: Option<String>,
    },
    /// 采集缺口
    Gaps {
        /// 会话号或 @last
        session: String,
    },
    /// 查看某条记录前后的事件
    Around {
        /// 会话号或 @last
        session: String,
        reference: String,
        #[arg(long)]
        window: Option<String>,
    },
    /// 跨会话搜索
    Search {
        /// 搜索词或筛选表达式
        text: String,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        kind: Option<String>,
    },
    /// 导出会话记录
    Export {
        /// 会话号或 @last
        session: String,
        /// 导出格式：jsonl、csv、md（markdown 也可）
        #[arg(long)]
        format: Option<String>,
        #[arg(short, long, help = "写入文件；省略则输出到标准输出")]
        output: Option<String>,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, help = "导出智能体、链路或 RPC（本版本未接入）")]
        include: Option<String>,
        #[arg(long)]
        redact_paths: bool,
        #[arg(long)]
        redact_hosts: bool,
    },
    /// 打开 AgentWatch 界面
    Ui {
        #[arg(long)]
        no_open: bool,
        #[arg(long)]
        port: Option<u16>,
    },
    /// 检查本机能力
    Doctor {
        #[arg(long, help = "性能与降级信息（本版本未接入）")]
        perf: bool,
    },
    /// 管理后台
    #[command(subcommand)]
    Daemon(DaemonCmd),
    /// 配置
    #[command(subcommand)]
    Config(ConfigCmd),
    /// 代理 CA（本版本未接入）
    #[command(subcommand, hide = true)]
    Proxy(ProxyCmd),
    /// 数据库
    #[command(subcommand)]
    Db(DbCmd),
    /// 开发用夹具（本版本未接入）
    #[command(subcommand, hide = true)]
    Fixtures(FixturesCmd),
    /// 监控组（本版本未接入）
    #[command(subcommand, hide = true)]
    Group(GroupCmd),
    /// 智能体实例（本版本未接入）
    #[command(hide = true)]
    Agents {
        session: Option<String>,
        #[arg(long)]
        group: Option<String>,
    },
    /// 智能体间链路（本版本未接入）
    #[command(hide = true)]
    Links {
        session: Option<String>,
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        min_evidence: Option<String>,
    },
    /// MCP 或 A2A 调用（本版本未接入）
    #[command(hide = true)]
    Rpc {
        session: String,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        target: Option<String>,
    },
    /// 委托链路（本版本未接入）
    #[command(hide = true)]
    Chain { session: String, reference: String },
    /// 跨主机离线合并
    Merge {
        a: String,
        b: String,
        #[arg(short, long)]
        output: Option<String>,
        /// NAT 映射，每行 `ip:port -> ip:port`，或一个 JSON 对象。缺省表示不改写。
        #[arg(long)]
        nat: Option<String>,
    },
    /// 由智能体自动调用，一般不用手动运行
    Hook {
        agent: String,
        #[arg(long)]
        session: Option<String>,
    },
    /// stdio 透明包装器（本版本未接入）
    #[command(hide = true)]
    McpTap {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// 单进程模式（本版本未接入）
    #[command(hide = true)]
    Dev {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// 版本
    Version {
        #[arg(long, help = "检查新版本（本版本未接入）")]
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
    Rename {
        session: String,
        name: String,
        /// 管理员操作其他用户会话时，明确指定会话主人
        #[arg(long)]
        owner: Option<String>,
    },
    /// 固定会话，不参与自动清理
    Pin {
        session: String,
        /// 管理员操作其他用户会话时，明确指定会话主人
        #[arg(long)]
        owner: Option<String>,
    },
    /// 取消固定
    Unpin {
        session: String,
        /// 管理员操作其他用户会话时，明确指定会话主人
        #[arg(long)]
        owner: Option<String>,
    },
    /// 删除会话
    Delete {
        #[arg(required = true)]
        sessions: Vec<String>,
        #[arg(long, help = "不再确认，直接删除（无法恢复）")]
        yes: bool,
        /// 管理员操作其他用户会话时，明确指定会话主人
        #[arg(long)]
        owner: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum DaemonCmd {
    /// 查看后台是否运行
    Status,
    /// 启动
    Start,
    /// 停止
    Stop,
    /// 重启
    Restart,
    /// 安装系统服务。没有 `--yes` 时只打印计划，不输出可执行命令
    Install {
        /// 确认后才输出供人工执行的 sc.exe 文本。本进程不运行它
        #[arg(long)]
        yes: bool,
    },
    /// 卸载系统服务（安装包提供实际安装与卸载）
    Uninstall {
        #[arg(long)]
        purge: bool,
        #[arg(long)]
        check: bool,
        /// 仅用于测试：`--purge` 时删除这个指定的数据目录，不触碰系统后台的数据
        #[arg(long, value_name = "DIR")]
        data_dir: Option<std::path::PathBuf>,
    },
    /// 日志：daemon 日志文件的最后若干行；`-f` 持续输出新增内容
    Logs {
        /// 持续输出新写入的行，Ctrl-C 结束
        #[arg(long, short = 'f')]
        follow: bool,
        /// 先输出最后多少行（最多 5000）
        #[arg(long, short = 'n', default_value_t = 200)]
        lines: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum RulesCmd {
    /// 已加载的规则
    List,
    /// 用夹具试跑一条规则。不连接 daemon，不读会话库
    Test {
        rule: String,
        fixture: String,
        /// 期望的 findings JSON。不一致时以非 0 退出
        #[arg(long)]
        expect: Option<String>,
    },
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
    /// 输出配置 JSON Schema（本版本未接入）
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
        /// 不再确认，直接继续
        #[arg(long)]
        yes: bool,
    },
    /// 从用户证书库移除
    Untrust {
        /// 不再确认，直接继续
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum DbCmd {
    /// 体积与各表行数
    Stats,
    /// 压缩数据库
    Vacuum {
        /// 不再确认，直接执行（无法恢复）
        #[arg(long)]
        yes: bool,
    },
    /// 更新数据库结构
    Migrate {
        #[arg(long)]
        dry_run: bool,
    },
    /// 删除旧会话（不可恢复）
    Purge {
        #[arg(long)]
        older_than: Option<String>,
        #[arg(long, help = "删除全部可删除的会话")]
        all: bool,
        #[arg(long, help = "不再确认，直接删除（无法恢复）")]
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
            DaemonCmd::Install { .. } => "daemon install",
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
            ProxyCmd::Untrust { .. } => "proxy untrust",
        },
        Command::Db(cmd) => match cmd {
            DbCmd::Stats => "db stats",
            DbCmd::Vacuum { .. } => "db vacuum",
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
