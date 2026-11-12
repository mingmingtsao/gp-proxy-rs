#![forbid(unsafe_code)]
use clap::{Parser, Subcommand};
use gp_proxy::{
    auth::AuthBinding,
    config::Config,
    control::{self, Authentication},
    control_local::LocalListener,
    credentials::{Credentials, PortalCredentials},
    gp::{GatewayClient, PortalClient},
    pac_history::PacHistory,
    policy::Policy,
    proxy::{ProxyConfig, ProxyServer},
    service::{self, AuthEvent, AuthFailure, AuthInput},
    session::TunnelConnector,
    terminal::{self, Terminal},
    tls,
};
use std::{
    future::Future,
    io::{self, Read},
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    process::ExitCode,
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    name = "gp-proxy",
    version,
    about = "GlobalProtect HTTP/SOCKS proxy without virtual network devices"
)]
struct Cli {
    #[arg(short, long, default_value = "gp-proxy.toml", global = true)]
    config: PathBuf,
    /// Load GP_USER, GP_PASSWORD and GP_GATEWAY without exporting process variables.
    #[arg(long, global = true, conflicts_with = "portal_env_file")]
    env_file: Option<PathBuf>,
    /// Portal-only GP_USER, GP_PASSWORD and GP_PORTAL; never changes the gateway.
    #[arg(long, global = true, conflicts_with = "env_file")]
    portal_env_file: Option<PathBuf>,
    /// Private local control directory (default: selected config with .control extension).
    #[arg(long, global = true)]
    control_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Internal deployment entry point: startup paths come only from admission.
    #[command(hide = true)]
    ManagedRun {
        #[arg(long)]
        runtime_dir: PathBuf,
        #[arg(long, value_parser = parse_instance)]
        installation: [u8; 16],
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        generation: u64,
        #[arg(long, value_parser = parse_release)]
        release: [u8; 32],
    },
    /// Inspect or manage an explicitly selected user service installation.
    Service {
        /// Private installation directory (default: current user's Application Support).
        #[arg(long, global = true)]
        state_dir: Option<PathBuf>,
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Stop this configured service and wait for its local cleanup report.
    /// Exit: 0 confirmed, 1 completion unobserved/incomplete, 3 remote outcome uncertain.
    Stop {
        /// Require this exact 32-hex-digit instance ID; never stop a replacement.
        #[arg(long, value_parser = parse_instance)]
        instance: Option<[u8; 16]>,
    },
    /// Read local service state without configuration or credentials. Exit: 0 available,
    /// 1 query failed, 2 invalid arguments, 3 service reached but unavailable.
    Status {
        /// Numeric loopback IP and HTTP proxy port (not the SOCKS5 port).
        #[arg(long, default_value = "127.0.0.1:8080", value_parser = parse_status_address)]
        address: SocketAddr,
    },
    /// Validate local configuration and TLS roots; do not connect to the gateway.
    Check,
    /// Print PAC for explicitly configured rules, without changing system settings.
    Pac,
    /// Perform one online login/tunnel check, then close the tunnel and log out.
    Probe {
        #[arg(long, default_value = "gp-proxy-rs")]
        computer: String,
        /// Optionally resolve this name using only the VPN's DNS and userspace stack.
        #[arg(long)]
        dns_name: Option<String>,
        /// Additional trusted corporate PEM root; certificate verification stays enabled.
        #[arg(long)]
        ca_file: Option<PathBuf>,
    },
    /// Run both loopback proxies; authenticate now or wait for explicit reauth.
    /// Ctrl-C stops all connections.
    Run {
        /// Keep four bounded diagnostic files in this private local directory.
        /// Created if absent; an existing directory must belong to this logger.
        #[arg(long)]
        log_dir: Option<PathBuf>,
        /// Bytes per file including its header (65536..=16777216).
        /// New directories default to 4194304; existing ones retain their size.
        #[arg(long, requires = "log_dir", value_parser = parse_log_file_bytes)]
        log_file_bytes: Option<u64>,
        /// Start offline without credentials; use reauth to authenticate later.
        /// Requires a supported private local control endpoint.
        #[arg(long, conflicts_with_all = ["username", "session_file", "password_stdin", "env_file", "portal_env_file", "interactive"])]
        wait_auth: bool,
        /// Allow hidden challenge answers from the controlling terminal.
        /// Implied by a hidden username/password prompt on supported Unix systems.
        #[arg(long, conflicts_with = "session_file")]
        interactive: bool,
        /// Gateway username for native password login (browser SAML is unsupported).
        #[arg(long, conflicts_with = "session_file")]
        username: Option<String>,
        /// Read password from stdin; otherwise use a hidden terminal prompt.
        #[arg(long, requires = "username")]
        password_stdin: bool,
        /// Client hostname used for native gateway login.
        #[arg(long, default_value = "gp-proxy-rs")]
        computer: String,
        /// Existing authorized gateway session JSON; must be private and gateway-bound.
        #[arg(long, conflicts_with = "username")]
        session_file: Option<PathBuf>,
    },
    /// Submit one new authentication to a waiting service; never retry automatically.
    Reauth {
        /// Allow hidden challenge answers; required with --env-file/--password-stdin.
        #[arg(long, conflicts_with = "session_file")]
        interactive: bool,
        #[arg(long, conflicts_with = "session_file")]
        username: Option<String>,
        #[arg(long, requires = "username")]
        password_stdin: bool,
        #[arg(long, default_value = "gp-proxy-rs")]
        computer: String,
        #[arg(long, conflicts_with = "username")]
        session_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Print the machine-readable management contract; do not read configuration.
    Capabilities,
    /// Inspect selected configuration and proposed private paths without creating files.
    Plan,
    /// Install a private copy; optionally start it without loading credentials.
    Install {
        #[arg(long)]
        start: bool,
    },
    /// Enable this installation at login and start it awaiting explicit reauth.
    Start,
    /// Cleanly stop this installation and remove its login startup definition.
    Stop,
    /// Validate and install this executable; preserve the current running state.
    Upgrade,
    /// Stop and remove owned releases/startup; preserve configuration and local data.
    Uninstall,
    /// Fence old instances and retain the committed release stopped; optionally start a new generation awaiting authentication.
    Recover {
        #[arg(long)]
        start: bool,
    },
    /// Inspect persisted deployment and matching IPC identity without credentials.
    Inspect,
}

fn parse_release(value: &str) -> Result<[u8; 32], String> {
    gp_proxy::managed_release::parse_release(value)
        .map_err(|_| "release must be a nonzero 64-character lowercase SHA-256".to_owned())
}

fn parse_log_file_bytes(value: &str) -> Result<u64, String> {
    let bytes = value
        .parse::<u64>()
        .map_err(|_| "log file size must be an integer number of bytes".to_string())?;
    if !(gp_proxy::logging::MIN_SLOT_BYTES..=gp_proxy::logging::MAX_SLOT_BYTES).contains(&bytes) {
        return Err("log file size must be between 65536 and 16777216 bytes".into());
    }
    Ok(bytes)
}

fn parse_instance(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("instance must contain exactly 32 hexadecimal digits".into());
    }
    let mut result = [0; 16];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid instance ID".to_string())?;
    }
    Ok(result)
}

#[derive(Debug, thiserror::Error)]
#[error("local cleanup completed, but remote logout or authentication outcome is unconfirmed")]
struct StopRemoteUnconfirmed;

fn parse_status_address(value: &str) -> Result<SocketAddr, String> {
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| "status address must be a numeric loopback IP:port".to_string())?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("status address must be loopback with a nonzero HTTP proxy port".into());
    }
    Ok(address)
}

impl Cli {
    fn validate_auth(&self) -> Result<(), clap::Error> {
        if matches!(
            self.command,
            Command::Service { .. } | Command::ManagedRun { .. }
        ) && (self.env_file.is_some() || self.portal_env_file.is_some())
        {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::ArgumentConflict,
                "service management does not accept credential files",
            ));
        }
        if matches!(self.command, Command::Service { .. }) && self.control_dir.is_some() {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::ArgumentConflict,
                "service management uses the control directory recorded in its installation",
            ));
        }
        if matches!(self.command, Command::ManagedRun { .. })
            && (self.control_dir.is_some() || self.config != std::path::Path::new("gp-proxy.toml"))
        {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::ArgumentConflict,
                "managed-run uses only its recorded startup paths",
            ));
        }
        if matches!(self.command, Command::Stop { .. })
            && (self.env_file.is_some() || self.portal_env_file.is_some())
        {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::ArgumentConflict,
                "stop does not accept credential files",
            ));
        }
        if matches!(self.command, Command::Probe { .. }) && self.portal_env_file.is_some() {
            return Err(clap::Error::raw(clap::error::ErrorKind::ArgumentConflict,
                "probe supports direct gateway credentials only; portal authentication requires run/reauth"));
        }
        if matches!(self.command, Command::Probe { .. }) && self.env_file.is_none() {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::MissingRequiredArgument,
                "probe requires an explicitly selected --env-file",
            ));
        }
        if let Command::Run {
            wait_auth: true,
            username,
            session_file,
            password_stdin,
            interactive,
            ..
        } = &self.command
        {
            // Global credential flags can occur on either side of `run`.
            // Reject them before any credential file or stdin is read.
            if username.is_some()
                || session_file.is_some()
                || *password_stdin
                || self.env_file.is_some()
                || self.portal_env_file.is_some()
                || *interactive
            {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::ArgumentConflict,
                    "run --wait-auth cannot be combined with authentication inputs",
                ));
            }
            return Ok(());
        }
        if let Command::Run {
            username,
            session_file,
            interactive,
            ..
        }
        | Command::Reauth {
            username,
            session_file,
            interactive,
            ..
        } = &self.command
        {
            if *interactive && !terminal::supported() {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::ValueValidation,
                    "--interactive requires supported cancellable terminal input",
                ));
            }
            if *interactive && session_file.is_some() {
                return Err(clap::Error::raw(
                    clap::error::ErrorKind::ArgumentConflict,
                    "--interactive cannot be combined with --session-file",
                ));
            }
            // Validate after global arguments are propagated to the subcommand.
            let sources = usize::from(username.is_some())
                + usize::from(session_file.is_some())
                + usize::from(self.env_file.is_some())
                + usize::from(self.portal_env_file.is_some());
            if sources != 1 {
                return Err(clap::Error::raw(
                    if sources == 0 {
                        clap::error::ErrorKind::MissingRequiredArgument
                    } else {
                        clap::error::ErrorKind::ArgumentConflict
                    },
                    "run/reauth require exactly one of --username, --session-file, --env-file or --portal-env-file; run also accepts --wait-auth without credentials",
                ));
            }
        }
        Ok(())
    }

    fn control_directory(&self) -> PathBuf {
        self.control_dir
            .clone()
            .unwrap_or_else(|| self.config.with_extension("control"))
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut cli = Cli::parse();
    // Argument conflicts must not create a log directory or touch credentials.
    // Status retains its existing config/credential-independent behavior.
    if !matches!(cli.command, Command::Status { .. }) {
        cli.validate_auth().unwrap_or_else(|error| error.exit());
    }
    if matches!(
        cli.command,
        Command::Service {
            action: ServiceAction::Capabilities,
            ..
        }
    ) {
        // A candidate probe must not initialize logs, inspect configuration or
        // create any local state. Its package version is not its compatibility.
        use std::io::Write;
        return match gp_proxy::managed_protocol::Capabilities::current()
            .encode()
            .and_then(|bytes| std::io::stdout().write_all(&bytes))
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        };
    }
    if let Command::ManagedRun {
        runtime_dir,
        installation,
        generation,
        release,
    } = &cli.command
    {
        let prepared = prepare_managed_run(runtime_dir, *installation, *generation, *release);
        cli = match prepared {
            Ok(cli) => cli,
            // Admission failure is before configuration, logger or proxy I/O.
            // The installation manager reports the bounded failure state.
            Err(_) => return ExitCode::FAILURE,
        };
    }
    let disk_logging = matches!(
        &cli.command,
        Command::Run {
            log_dir: Some(_),
            ..
        }
    );
    let logging = match &cli.command {
        Command::Run {
            log_dir: Some(directory),
            log_file_bytes,
            ..
        } => gp_proxy::logging::init_file(directory.clone(), *log_file_bytes),
        _ => gp_proxy::logging::init(),
    };
    let logs = match logging {
        Ok(logs) => logs,
        Err(error) => {
            // A requested disk sink is mandatory for this run. Only a bounded
            // startup diagnostic may use stderr; never continue the service or
            // synchronously print arbitrary filesystem error/path contents.
            if disk_logging {
                if let Ok(diagnostic) = gp_proxy::logging::init() {
                    tracing::error!(kind = ?error.kind(), "logging initialization failed; service was not started");
                    diagnostic.shutdown();
                }
            }
            return ExitCode::FAILURE;
        }
    };
    let code = match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Result's default Termination implementation writes stderr
            // synchronously, which can hang an otherwise cleaned-up service.
            tracing::error!(?error, "command failed");
            if error.is::<StopRemoteUnconfirmed>() {
                ExitCode::from(3)
            } else {
                ExitCode::FAILURE
            }
        }
    };
    logs.shutdown();
    code
}

fn prepare_managed_run(
    runtime_dir: &std::path::Path,
    installation: [u8; 16],
    generation: u64,
    release: [u8; 32],
) -> std::io::Result<Cli> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (runtime_dir, installation, generation, release);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "managed services require macOS",
        ))
    }
    #[cfg(target_os = "macos")]
    {
        if rustix::process::geteuid().as_raw() == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "managed services require a non-root user",
            ));
        }
        let identity = gp_proxy::managed_protocol::ManagedIdentity {
            installation,
            generation,
            release,
        };
        let lease = gp_proxy::managed_runtime::RuntimeLease::acquire(runtime_dir, &identity)?;
        let spec = lease.spec().clone();
        gp_proxy::managed_release::verify_running(&spec.binary, &release)?;
        lease.install_process()?;
        Ok(Cli {
            config: spec.config,
            env_file: None,
            portal_env_file: None,
            control_dir: Some(spec.control),
            command: Command::Run {
                log_dir: Some(spec.logs),
                log_file_bytes: None,
                wait_auth: true,
                interactive: false,
                username: None,
                password_stdin: false,
                computer: "gp-proxy-rs".to_owned(),
                session_file: None,
            },
        })
    }
}

fn print_deployment_report(report: &gp_proxy::deployment::DeploymentReport) -> AppResult<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    if report.remote_outcome_unknown
        || report.maintenance_outcome_unknown
        || report.logout_unconfirmed != 0
        || report.retired_jobs != 0
        || report.cleanup.as_ref().is_some_and(|completion| {
            completion.cleanup.logout_unconfirmed != 0
                || completion.cleanup.remote_outcome_unknown != 0
        })
    {
        return Err(StopRemoteUnconfirmed.into());
    }
    Ok(())
}

async fn run(cli: Cli) -> AppResult<()> {
    if let Command::Service { state_dir, action } = &cli.command {
        match action {
            ServiceAction::Plan => {
                let plan = gp_proxy::deployment::plan(state_dir.as_deref(), &cli.config)?;
                println!("{}", serde_json::to_string_pretty(&plan)?);
                return Ok(());
            }
            ServiceAction::Capabilities => unreachable!("capabilities precede logging"),
            ServiceAction::Install { start } => {
                let plan = gp_proxy::deployment::plan(state_dir.as_deref(), &cli.config)?;
                let report = gp_proxy::deployment::install(plan, *start).await?;
                return print_deployment_report(&report);
            }
            _ => {
                let root = match state_dir {
                    Some(path) => path.clone(),
                    None => gp_proxy::deployment::default_state_directory()?,
                };
                let report = match action {
                    ServiceAction::Inspect => gp_proxy::deployment::inspect(&root).await?,
                    ServiceAction::Recover { start } => {
                        let recovered = gp_proxy::deployment::recover(&root).await?;
                        if *start {
                            gp_proxy::deployment::change(
                                &root,
                                gp_proxy::deployment::ManageAction::Start,
                            )
                            .await?
                        } else {
                            recovered
                        }
                    }
                    ServiceAction::Start
                    | ServiceAction::Stop
                    | ServiceAction::Upgrade
                    | ServiceAction::Uninstall => {
                        use gp_proxy::deployment::ManageAction;
                        let operation = match action {
                            ServiceAction::Start => ManageAction::Start,
                            ServiceAction::Stop => ManageAction::Stop,
                            ServiceAction::Upgrade => ManageAction::Upgrade,
                            ServiceAction::Uninstall => ManageAction::Uninstall,
                            _ => unreachable!(),
                        };
                        gp_proxy::deployment::change(&root, operation).await?
                    }
                    _ => unreachable!(),
                };
                return print_deployment_report(&report);
            }
        }
    }
    if let Command::Status { address } = &cli.command {
        match gp_proxy::status::query(*address).await {
            Ok(snapshot) => {
                println!("{}", serde_json::to_string(&snapshot)?);
                if !snapshot.available {
                    std::process::exit(3);
                }
                return Ok(());
            }
            Err(error) => {
                // Do not echo a response body or arbitrary server error text.
                eprintln!("Local status query failed ({:?}).", error.kind());
                std::process::exit(1);
            }
        }
    }
    if let Command::Stop { instance } = &cli.command {
        let config = Config::read(&cli.config)?;
        let binding = config.auth_binding()?;
        let report = control::stop(&cli.control_directory(), &binding, *instance).await?;
        println!("{}", serde_json::to_string(&report)?);
        if !report.local_cleanup_complete {
            return Err("service reported incomplete local cleanup".into());
        }
        if report.cleanup.logout_unconfirmed != 0 || report.cleanup.remote_outcome_unknown != 0 {
            return Err(StopRemoteUnconfirmed.into());
        }
        return Ok(());
    }
    if let Command::Reauth {
        interactive,
        username,
        password_stdin,
        computer,
        session_file,
    } = &cli.command
    {
        return reauthenticate(
            &cli,
            username.as_deref(),
            *password_stdin,
            computer,
            session_file.as_deref(),
            *interactive,
        )
        .await;
    }
    let control_directory = cli.control_directory();
    let explicit_control = cli.control_dir.is_some();
    if let Command::Probe {
        computer,
        dns_name,
        ca_file,
    } = &cli.command
    {
        if let Some(name) = dns_name {
            let target = gp_proxy::proxy::Target::new(name, 53)?;
            if target.host.parse::<std::net::IpAddr>().is_ok() {
                return Err("probe DNS query requires a hostname, not an IP literal".into());
            }
        }
        // Probe remains an explicit direct-only operation, independent of proxy configuration.
        let credentials =
            Credentials::read(cli.env_file.as_deref().ok_or("probe requires --env-file")?)?;
        let client = GatewayClient::new(
            url::Url::parse(&credentials.gateway)?,
            tls::client_config(ca_file.as_deref())?,
            gp_proxy::gp::ResumptionPolicy::Memory {
                tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
            },
        )?;
        let shutdown = CancellationToken::new();
        return run_until_signal(&shutdown, async {
            gp_proxy::probe::run(
                &client,
                credentials,
                computer,
                dns_name.as_deref(),
                shutdown.clone(),
            )
            .await?;
            Ok(())
        })
        .await;
    }
    // Parse the selected nonsecret mode before any credential file. Direct
    // overrides are the only legacy exception and are scoped by the provider.
    let mut credentials = None;
    let mut config = if let Some(path) = cli.env_file.as_deref() {
        Config::read_with_gateway_provider(&cli.config, || {
            let loaded = Credentials::read(path)?;
            let gateway = loaded.gateway.clone();
            credentials = Some(loaded);
            Ok(gateway)
        })?
    } else {
        Config::read(&cli.config)?
    };
    let binding = config.auth_binding()?;
    if matches!(
        &cli.command,
        Command::Run {
            session_file: Some(_),
            ..
        }
    ) && binding.portal_origin().is_some()
    {
        return Err("--session-file is not supported in portal mode".into());
    }
    let portal_credentials = if let Some(path) = cli.portal_env_file.as_deref() {
        if binding.portal_origin().is_none() {
            return Err("--portal-env-file requires configured portal mode".into());
        }
        let loaded = PortalCredentials::read(path)?;
        if !AuthBinding::via_portal(&loaded.portal, binding.gateway())?.matches(&binding) {
            return Err(
                "credential portal differs from configured portal; nothing submitted".into(),
            );
        }
        Some(loaded)
    } else {
        None
    };
    let local_policy = Policy::new(config.domains.clone(), config.networks.clone())?;
    match cli.command {
        Command::ManagedRun { .. } => unreachable!("managed admission handled before logging"),
        Command::Service { .. } => unreachable!("service management handled before configuration"),
        Command::Status { .. } => {
            unreachable!("status handled before configuration or credentials")
        }
        Command::Stop { .. } => unreachable!("stop handled before credentials"),
        Command::Probe { .. } => unreachable!("probe handled before proxy configuration"),
        Command::Reauth { .. } => unreachable!("reauth handled before credentials"),
        Command::Check => {
            // Constructors validate the platform's explicit authentication profile
            // and independent roots without opening a network connection.
            Clients::new(&config)?;
            PacHistory::read(
                config
                    .pac_history_file
                    .as_deref()
                    .expect("configuration history path"),
            )?;
            println!("Configuration valid. HTTP {}, SOCKS5 {}. No gateway connection or system changes made.", config.http_listen, config.socks_listen);
            Ok(())
        }
        Command::Pac => {
            if config.trust_gateway_routes {
                return Err("gateway policy requires authentication; use the running service's /proxy.pac endpoint".into());
            }
            let history = PacHistory::read(
                config
                    .pac_history_file
                    .as_deref()
                    .expect("configuration history path"),
            )?;
            print!(
                "{}",
                history
                    .merge_classification(&local_policy)?
                    .pac(config.http_listen)
            );
            Ok(())
        }
        Command::Run {
            wait_auth,
            interactive,
            username,
            password_stdin,
            computer,
            session_file,
            ..
        } => {
            // Acquire the one-writer lock and commit local classification before
            // authentication. All failure paths release the lock through Drop.
            config.pac_history = Some(Arc::new(PacHistory::open(
                config
                    .pac_history_file
                    .as_deref()
                    .expect("configuration history path"),
                &local_policy,
            )?));
            tracing::warn!("experimental client: real gateway coverage and deployment limitations are documented in README");
            let clients = Clients::new(&config)?;
            if !wait_auth {
                display_binding(&binding);
            }
            // Own both listeners before prompting or sending any login request.
            // Reserving and then dropping them would leave a race during login;
            // this exact server is transferred to authenticated startup instead.
            let server = bind_proxy(&config).await?;
            // Keep the same control lock/listener across the password prompt.
            // The persistent owner record permits safe recovery if a default
            // signal kills this process before Tokio's handlers are installed.
            // An offline process without a usable control endpoint could never
            // authenticate. Unsupported platforms must reject this mode.
            let control = bind_control(&control_directory, explicit_control || wait_auth)?;
            let mut terminal = open_terminal(interaction_enabled(
                username.is_some(),
                password_stdin,
                interactive,
            ))?;
            // Stdin (and the unsupported-platform legacy initial prompt) stays
            // outside installed handlers: those synchronous reads cannot be
            // cancelled. Supported terminal input is asynchronous below.
            let password = username
                .as_ref()
                .filter(|_| password_stdin || terminal.is_none())
                .map(|_| read_password(password_stdin))
                .transpose()?;
            let shutdown = CancellationToken::new();
            run_until_signal(&shutdown, async {
                let password = if username.is_some() && password.is_none() {
                    match read_terminal(
                        terminal.as_mut().ok_or("missing terminal")?,
                        "GlobalProtect password: ",
                        &shutdown,
                    )
                    .await
                    {
                        Ok(password) => Some(password),
                        Err(_) if shutdown.is_cancelled() => return Ok(()),
                        Err(error) => return Err(error.into()),
                    }
                } else {
                    password
                };
                // Import a cookie only after signal handlers were installed;
                // failure to install handlers must not strand an imported session.
                let input = if wait_auth {
                    None
                } else if let Some(path) = session_file {
                    Some(AuthInput::Session(gp_proxy::session_file::read(
                        &path,
                        &config.gateway,
                    )?))
                } else if let Some(credentials) = portal_credentials {
                    Some(AuthInput::PortalPassword {
                        portal: credentials.portal,
                        user: credentials.user.to_string(),
                        password: credentials.password,
                        computer,
                    })
                } else if let Some(credentials) = credentials {
                    Some(AuthInput::Password {
                        user: credentials.user.to_string(),
                        password: credentials.password,
                        computer,
                    })
                } else {
                    Some(password_input(
                        &binding,
                        username.ok_or("missing username")?,
                        password.ok_or("missing password")?,
                        computer,
                    ))
                };
                serve_local(
                    config,
                    clients,
                    input,
                    shutdown.clone(),
                    server,
                    control,
                    terminal,
                )
                .await
            })
            .await
        }
    }
}

struct Clients {
    gateway: GatewayClient,
    portal: Option<PortalClient>,
}

impl From<GatewayClient> for Clients {
    fn from(gateway: GatewayClient) -> Self {
        Self {
            gateway,
            portal: None,
        }
    }
}

impl Clients {
    fn new(config: &Config) -> AppResult<Self> {
        let policy = gp_proxy::gp::ResumptionPolicy::Memory {
            tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
        };
        let gateway = GatewayClient::new(
            url::Url::parse(&config.gateway)?,
            tls::client_config(config.ca_file.as_deref())?,
            policy,
        )?;
        let portal = config
            .portal
            .as_deref()
            .map(|origin| -> AppResult<_> {
                Ok(PortalClient::new(
                    url::Url::parse(origin)?,
                    url::Url::parse(&config.gateway)?,
                    tls::client_config(config.portal_ca_file.as_deref())?,
                    policy,
                )?)
            })
            .transpose()?;
        Ok(Self { gateway, portal })
    }
}

fn display_binding(binding: &AuthBinding) {
    match binding.portal_origin() {
        Some(portal) => eprintln!(
            "Authentication mode: portal {portal}; selected gateway {}.",
            binding.gateway()
        ),
        None => eprintln!("Authentication mode: direct gateway {}.", binding.gateway()),
    }
}

fn password_input(
    binding: &AuthBinding,
    user: String,
    password: Zeroizing<String>,
    computer: String,
) -> AuthInput {
    match binding.portal_origin() {
        Some(portal) => AuthInput::PortalPassword {
            portal: portal.to_owned(),
            user,
            password,
            computer,
        },
        None => AuthInput::Password {
            user,
            password,
            computer,
        },
    }
}

fn password_authentication(
    binding: &AuthBinding,
    user: Zeroizing<String>,
    password: Zeroizing<String>,
    computer: String,
) -> Authentication {
    match binding.portal_origin() {
        Some(portal) => Authentication::PortalPassword {
            portal: portal.to_owned(),
            user,
            password,
            computer,
        },
        None => Authentication::Password {
            user,
            password,
            computer,
        },
    }
}

fn interaction_enabled(username: bool, password_stdin: bool, explicit: bool) -> bool {
    explicit || (terminal::supported() && username && !password_stdin)
}

fn open_terminal(enabled: bool) -> io::Result<Option<Terminal>> {
    enabled.then(Terminal::open).transpose()
}

async fn cancellable_input(
    shutdown: &CancellationToken,
    input: impl Future<Output = io::Result<Zeroizing<String>>>,
) -> io::Result<Zeroizing<String>> {
    let result = tokio::select! {
        biased;
        _ = shutdown.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "terminal input cancelled")),
        result = input => result,
    };
    // The terminal deliberately disables ISIG while reading. Typed Ctrl-C
    // becomes Interrupted and must trigger the same cleanup as external INT.
    if matches!(&result, Err(error) if error.kind() == io::ErrorKind::Interrupted) {
        shutdown.cancel();
    }
    result
}

async fn read_terminal(
    terminal: &mut Terminal,
    prompt: &str,
    shutdown: &CancellationToken,
) -> io::Result<Zeroizing<String>> {
    cancellable_input(shutdown, terminal.read_secret(prompt)).await
}

fn challenge_label(round: u8, prompt: &str) -> String {
    format!("GlobalProtect challenge {round}: {prompt} Answer: ")
}

struct ChallengeTerminal<'a> {
    terminal: &'a mut Terminal,
    shutdown: &'a CancellationToken,
}

impl control::ChallengeHandler for ChallengeTerminal<'_> {
    fn respond(
        &mut self,
        prompt: control::ChallengePrompt,
    ) -> Pin<Box<dyn Future<Output = io::Result<Zeroizing<String>>> + Send + '_>> {
        Box::pin(async move {
            let label = challenge_label(prompt.round(), prompt.prompt());
            read_terminal(self.terminal, &label, self.shutdown).await
        })
    }
}

async fn reauthenticate(
    cli: &Cli,
    username: Option<&str>,
    password_stdin: bool,
    computer: &str,
    session_file: Option<&std::path::Path>,
    interactive: bool,
) -> AppResult<()> {
    let directory = cli.control_directory();
    // The preflight must precede even opening the TTY, as well as every secret
    // file/stdin read. The actual submit still rechecks this service identity.
    let preflight = control::preflight(&directory).await?;
    let mut direct_credentials = None;
    let configured = if let Some(path) = cli.env_file.as_deref() {
        if preflight.binding().portal_origin().is_some() {
            return Err("--env-file cannot authenticate a portal service".into());
        }
        Config::read_with_gateway_provider(&cli.config, || {
            let loaded = Credentials::read(path)?;
            let gateway = loaded.gateway.clone();
            direct_credentials = Some(loaded);
            Ok(gateway)
        })?
    } else {
        Config::read(&cli.config)?
    };
    let binding = configured.auth_binding()?;
    if !preflight.matches_binding(&binding) {
        return Err(
            "configured authentication binding differs from the running service; nothing submitted"
                .into(),
        );
    }
    if session_file.is_some() && binding.portal_origin().is_some() {
        return Err("--session-file is not supported in portal mode".into());
    }
    if cli.portal_env_file.is_some() && binding.portal_origin().is_none() {
        return Err("--portal-env-file requires configured portal mode".into());
    }
    // Both the role and every destination have been checked before opening the
    // TTY, reading stdin, or reading a portal/session secret file.
    display_binding(&binding);
    let mut terminal = open_terminal(interaction_enabled(
        username.is_some(),
        password_stdin,
        interactive,
    ))?;
    let supplied = if let Some(credentials) = direct_credentials {
        Some(password_authentication(
            &binding,
            credentials.user,
            credentials.password,
            computer.to_owned(),
        ))
    } else if let Some(path) = cli.portal_env_file.as_deref() {
        let credentials = PortalCredentials::read(path)?;
        if !AuthBinding::via_portal(&credentials.portal, binding.gateway())?.matches(&binding) {
            return Err(
                "credential portal differs from configured portal; nothing submitted".into(),
            );
        }
        Some(password_authentication(
            &binding,
            credentials.user,
            credentials.password,
            computer.to_owned(),
        ))
    } else if let Some(user) = username {
        if password_stdin || terminal.is_none() {
            Some(password_authentication(
                &binding,
                Zeroizing::new(user.to_owned()),
                read_password(password_stdin)?,
                computer.to_owned(),
            ))
        } else {
            None
        }
    } else {
        None
    };
    let shutdown = CancellationToken::new();
    run_until_signal(&shutdown, async {
        if shutdown.is_cancelled() {
            return Ok(());
        }
        let authentication = if let Some(supplied) = supplied {
            supplied
        } else if let Some(path) = session_file {
            Authentication::Session {
                source: gp_proxy::session_file::read_for_transfer(path, preflight.gateway())?,
            }
        } else {
            let password = match read_terminal(
                terminal.as_mut().ok_or("missing terminal")?,
                "GlobalProtect password: ",
                &shutdown,
            )
            .await
            {
                Ok(password) => password,
                Err(_) if shutdown.is_cancelled() => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            password_authentication(
                &binding,
                Zeroizing::new(username.ok_or("missing username")?.to_owned()),
                password,
                computer.to_owned(),
            )
        };
        let authentication = async {
            if let Some(terminal) = terminal.as_mut() {
                let mut handler = ChallengeTerminal {
                    terminal,
                    shutdown: &shutdown,
                };
                control::authenticate_interactive(
                    &directory,
                    preflight,
                    authentication,
                    &mut handler,
                )
                .await
            } else {
                control::authenticate(&directory, preflight, authentication).await
            }
        };
        let result = tokio::select! {
            biased;
            // Only this short-lived IPC client is dropped. The running service
            // owns any in-flight login/cookie and performs bounded cleanup.
            _ = shutdown.cancelled() => return Ok(()),
            result = authentication => result,
        };
        match result {
            Ok(()) => {
                println!("Authentication accepted. Use status to confirm tunnel availability.");
                Ok(())
            }
            Err(_) if shutdown.is_cancelled() => Ok(()),
            Err(error) => Err(format!(
                "{error}. Do not retry automatically; check status before submitting again."
            )
            .into()),
        }
    })
    .await
}

fn read_password(stdin: bool) -> AppResult<Zeroizing<String>> {
    if !stdin {
        let password = Zeroizing::new(rpassword::prompt_password("GlobalProtect password: ")?);
        if password.len() > 8192 {
            return Err("password exceeds limit".into());
        }
        return Ok(password);
    }
    read_password_from(&mut io::stdin())
}

fn read_password_from(reader: &mut impl Read) -> AppResult<Zeroizing<String>> {
    // Keep the previous 8195-byte read ceiling (8192 bytes plus CRLF and an
    // overflow sentinel), without reallocating a secret-bearing buffer.
    let mut bytes = Zeroizing::new(vec![0; 8195]);
    let mut filled = 0;
    while filled < bytes.len() {
        match reader.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(size) => filled += size,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(io::Error::new(error.kind(), "cannot read password input").into())
            }
        }
    }
    bytes.truncate(filled);
    let mut password = match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(password) => Zeroizing::new(password),
        Err(error) => {
            let _discard = Zeroizing::new(error.into_bytes());
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "password input is not valid UTF-8",
            )
            .into());
        }
    };
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    if password.len() > 8192 {
        return Err("password exceeds limit".into());
    }
    Ok(password)
}

async fn bind_proxy(config: &Config) -> io::Result<ProxyServer> {
    ProxyServer::bind(ProxyConfig {
        http_addr: config.http_listen,
        socks_addr: config.socks_listen,
        max_connections: config.max_connections,
        handshake_timeout: Duration::from_secs(config.connect_timeout_secs),
        idle_timeout: Duration::from_secs(config.idle_timeout_secs),
    })
    .await
}

fn bind_control(directory: &std::path::Path, explicit: bool) -> io::Result<Option<LocalListener>> {
    #[cfg(all(
        any(target_os = "macos", target_os = "linux"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let _ = explicit;
        LocalListener::bind(directory).map(Some)
    }
    #[cfg(not(all(
        any(target_os = "macos", target_os = "linux"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        if explicit {
            LocalListener::bind(directory).map(Some)
        } else {
            Ok(None)
        }
    }
}

async fn serve_local(
    config: Config,
    clients: Clients,
    input: Option<AuthInput>,
    shutdown: CancellationToken,
    server: ProxyServer,
    control: Option<LocalListener>,
    mut terminal: Option<Terminal>,
) -> AppResult<()> {
    let Clients {
        gateway: client,
        portal,
    } = clients;
    if shutdown.is_cancelled() {
        if let Some(AuthInput::Session(session)) = input {
            service::discard_session(&client, session).await;
        }
        return Ok(());
    }
    if input.is_none() && control.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "run --wait-auth requires a supported private control endpoint",
        )
        .into());
    }
    // Until admission succeeds the service has not taken ownership of an
    // imported cookie. Preserve only that cookie for cleanup of local setup
    // failures; drop the backup before starting the first authentication.
    let imported = match &input {
        Some(AuthInput::Session(session)) => Some(session.clone()),
        _ => None,
    };
    let cleanup_client = client.clone();
    let setup = (|| -> AppResult<_> {
        let local_policy = Policy::new(config.domains.clone(), config.networks.clone())?;
        let pac = match &config.pac_history {
            Some(history) => history.remember(&local_policy)?,
            None => local_policy,
        };
        let (pac_tx, pac_rx) = watch::channel(Arc::new(pac));
        let connector = Arc::new(TunnelConnector::default());
        let binding = config.auth_binding()?;
        let gateway = binding.gateway().to_owned();
        let (handle, service) = service::new_with_portal(
            config,
            client,
            portal,
            connector.clone(),
            pac_tx,
            shutdown.clone(),
        )?;
        // When present, reserve the initial operation before admitting IPC
        // clients. With no input, the service stays Waiting without a login
        // lease, credential request or retry; only explicit reauth can start it.
        let initial = input
            .map(|input| {
                let operation = handle.try_authenticate_bound(
                    input,
                    &binding,
                    CancellationToken::new(),
                    terminal.is_some(),
                );
                operation.map_err(|_| "initial authentication could not start")
            })
            .transpose()?;
        Ok((pac_rx, connector, gateway, handle, service, initial))
    })();
    let (pac_rx, connector, gateway, handle, service, initial) = match setup {
        Ok(setup) => setup,
        Err(error) => {
            if let Some(session) = imported {
                service::discard_session(&cleanup_client, session).await;
            }
            return Err(error);
        }
    };
    drop(imported);
    drop(cleanup_client);
    // The control instance exists, but no control/proxy/service worker can
    // accept authentication before its durable Active record is acknowledged.
    // ManagedRun is always wait-auth; credentials are never persisted here.
    let incarnation = if gp_proxy::managed_runtime::current_identity().is_some() {
        let instance = control
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "managed lifecycle requires a control instance",
                )
            })?
            .instance_id();
        Some(gp_proxy::managed_io::begin(instance).await?)
    } else {
        None
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut service_task = tokio::spawn(service.run());
    let mut proxy_task = tokio::spawn(server.serve(connector.clone(), pac_rx, shutdown_rx));
    let control_shutdown = shutdown.clone();
    let control_enabled = control.is_some();
    // The monitor owns service lifetime even on platforms where ordinary
    // authenticated run has no control worker holding a sender.
    let service_handle = handle.clone();
    // Closing the control acceptor must not release ownership while the
    // service is still logging out or any proxy/initial worker remains alive.
    let namespace = control.as_ref().map(LocalListener::retain_namespace);
    let (stop_sender, mut stop_receiver) = control::stop_channel();
    let mut control_task = tokio::spawn(async move {
        if let Some(listener) = control {
            control::serve_managed(listener, gateway, handle, control_shutdown, stop_sender).await
        } else {
            control_shutdown.cancelled().await;
            Ok(())
        }
    });
    let waiting_for_authentication = initial.is_none();
    let initial_shutdown = shutdown.clone();
    let mut initial_task = tokio::spawn(async move {
        if let Some(mut initial) = initial {
            let result = loop {
                let event = tokio::select! {
                    biased;
                    _ = initial_shutdown.cancelled() => break Err(AuthFailure::Cancelled),
                    event = initial.next_event() => event,
                };
                match event {
                    Ok(AuthEvent::Prepared) => break initial.commit(),
                    Ok(AuthEvent::Challenge(request)) => {
                        let Some(terminal) = terminal.as_mut() else {
                            break Err(AuthFailure::InteractiveRequired);
                        };
                        let label = challenge_label(request.round(), request.prompt());
                        let answer = request.respond_with(read_terminal(
                            terminal,
                            &label,
                            &initial_shutdown,
                        ));
                        let result = tokio::select! {
                            biased;
                            _ = initial_shutdown.cancelled() => break Err(AuthFailure::Cancelled),
                            result = answer => result,
                        };
                        if let Err(reason) = result {
                            break Err(reason);
                        }
                    }
                    Err(reason) => break Err(reason),
                }
            };
            if let Err(reason) = result {
                tracing::warn!(
                    ?reason,
                    "initial authentication ended; business egress remains closed"
                );
            }
        }
    });
    tracing::info!(
        control_enabled,
        waiting_for_authentication,
        "loopback proxies listening; PAC and status available; use reauth when authentication is required"
    );
    let mut proxy_joined = false;
    let mut service_joined = false;
    let mut control_joined = false;
    let mut initial_joined = false;
    let mut fatal = false;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            result = &mut initial_task, if !initial_joined => {
                initial_joined = true;
                if result.is_err() { fatal = true; break; }
            },
            _ = &mut proxy_task => { proxy_joined = true; fatal = true; break; },
            _ = &mut service_task => { service_joined = true; fatal = true; break; },
            _ = &mut control_task => { control_joined = true; fatal = true; break; },
        }
    }
    service_handle.request_stop();
    shutdown_tx.send_replace(true);
    if !initial_joined && initial_task.await.is_err() {
        fatal = true;
    }
    if !control_joined && !matches!(control_task.await, Ok(Ok(()))) {
        fatal = true;
    }
    if !service_joined && service_task.await.is_err() {
        fatal = true;
    }
    if !proxy_joined && !matches!(proxy_task.await, Ok(Ok(()))) {
        fatal = true;
    }
    let completion = service_handle.completion();
    if completion.is_none() {
        fatal = true;
    }
    let mut report = control::StopReport {
        local_cleanup_complete: !fatal && completion.is_some(),
        cleanup: completion.unwrap_or_default(),
    };
    // Persist even on ordinary SIGTERM without a StopResponder. This record
    // describes this exact joined instance, not delivery of an IPC receipt.
    if let Some(stamp) = incarnation {
        if report.local_cleanup_complete
            && gp_proxy::managed_io::finish(stamp, report.clone())
                .await
                .is_err()
        {
            fatal = true;
            report.local_cleanup_complete = false;
            tracing::warn!("managed lifecycle terminal write was not acknowledged; cleanup remains unconfirmed");
        }
    }
    // All local tasks have joined. The final response must follow releasing
    // the namespace; a client must never mistake a vanished socket for this
    // barrier, and a missing response leaves completion unobserved.
    if let Some(namespace) = namespace {
        namespace.release();
    }
    if let Ok(responder) = stop_receiver.try_recv() {
        if responder.complete(report).await.is_err() {
            tracing::warn!("stop cleanup report could not be delivered; cleanup was not retried");
        }
    }
    if fatal {
        return Err(
            "local service task stopped unexpectedly; business egress closed, cleanup may be incomplete"
                .into(),
        );
    }
    Ok(())
}

async fn run_until_signal<T>(
    shutdown: &CancellationToken,
    work: impl Future<Output = AppResult<T>>,
) -> AppResult<T> {
    // Register Unix handlers before polling work, including authentication.
    let signal = termination_signal()?;
    drive_until_signal(shutdown, work, signal).await
}

async fn drive_until_signal<T>(
    shutdown: &CancellationToken,
    work: impl Future<Output = AppResult<T>>,
    signal: impl Future<Output = io::Result<()>>,
) -> AppResult<T> {
    tokio::pin!(work);
    tokio::select! {
        result = &mut work => result,
        signal_result = signal => {
            shutdown.cancel();
            // Never drop authenticated work: it must close its tasks and logout.
            let result = work.await;
            signal_result?;
            result
        }
    }
}

fn termination_signal() -> io::Result<impl Future<Output = io::Result<()>>> {
    #[cfg(unix)]
    {
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        Ok(async move {
            tokio::select! { _ = interrupt.recv() => Ok(()), _ = terminate.recv() => Ok(()) }
        })
    }
    #[cfg(not(unix))]
    {
        Ok(tokio::signal::ctrl_c())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gp_proxy::gp::Session;
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn password_stdin_preserves_fragmented_utf8_without_reallocating() {
        const INPUT: &[u8] = "synthetic-密码-🔐\r\n".as_bytes();
        struct Fragmented {
            position: usize,
            base: Option<usize>,
            interrupted: bool,
        }
        impl Read for Fragmented {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                assert!(!output.is_empty());
                let base = output.as_ptr() as usize - self.position;
                assert_eq!(*self.base.get_or_insert(base), base);
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                if self.position == INPUT.len() {
                    return Ok(0);
                }
                output[0] = INPUT[self.position];
                self.position += 1;
                Ok(1)
            }
        }
        let mut reader = Fragmented {
            position: 0,
            base: None,
            interrupted: false,
        };
        let password = read_password_from(&mut reader).unwrap();
        assert_eq!(password.as_str(), "synthetic-密码-🔐");
        assert_eq!(Some(password.as_ptr() as usize), reader.base);
        assert!(password.capacity() >= 8195);
    }

    #[test]
    fn password_stdin_keeps_exact_limit_line_endings_and_eof_semantics() {
        for ending in ["", "\n", "\r\n"] {
            let input = format!("{}{ending}", "x".repeat(8192));
            let password = read_password_from(&mut input.as_bytes()).unwrap();
            assert_eq!(password.len(), 8192);
            assert!(password.bytes().all(|byte| byte == b'x'));
        }
        assert!(read_password_from(&mut io::empty()).unwrap().is_empty());
        assert_eq!(
            read_password_from(&mut b"keep-lone-cr\r".as_slice())
                .unwrap()
                .as_str(),
            "keep-lone-cr\r"
        );
        for length in [8193, 8194, 8195, 16384] {
            let mut reader = io::Cursor::new(vec![b'x'; length]);
            let error = read_password_from(&mut reader).unwrap_err();
            assert_eq!(error.to_string(), "password exceeds limit");
            assert_eq!(reader.position(), length.min(8195) as u64);
        }
    }

    #[test]
    fn password_stdin_rejects_invalid_utf8_and_redacts_partial_read_errors() {
        let error = read_password_from(&mut b"synthetic-secret\xff".as_slice()).unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(error.to_string(), "password input is not valid UTF-8");

        struct FailsAfterPrefix(bool);
        impl Read for FailsAfterPrefix {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if std::mem::replace(&mut self.0, true) {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "synthetic-secret-must-not-appear",
                    ));
                }
                output[..6].copy_from_slice(b"secret");
                Ok(6)
            }
        }
        let error = read_password_from(&mut FailsAfterPrefix(false)).unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(error.to_string(), "cannot read password input");
    }

    async fn startup_gateway(
        config_response: Option<&'static str>,
    ) -> (GatewayClient, String, tokio::task::JoinHandle<()>) {
        let certs =
            CertificateDer::pem_slice_iter(include_bytes!("gp/testdata/localhost-cert.pem"))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key =
            PrivateKeyDer::from_pem_slice(include_bytes!("gp/testdata/localhost-key.pem")).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certs[0].clone()).unwrap();
        let client_tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway = url::Url::parse(&format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
            for (path, response) in config_response
                .into_iter()
                .map(|response| ("getconfig.esp", response))
                .chain(std::iter::once((
                    "logout.esp",
                    "<response status='success'/>",
                )))
            {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 16384);
                    header.push(tls.read_u8().await.unwrap());
                }
                let header = std::str::from_utf8(&header).unwrap();
                assert!(header.starts_with(&format!("POST /ssl-vpn/{path} HTTP/1.1\r\n")));
                let length: usize = header
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                assert!(length < 65536);
                let mut body = vec![0; length];
                tls.read_exact(&mut body).await.unwrap();
                tls.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{response}",
                        response.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
                tls.shutdown().await.unwrap();
            }
        });
        (
            GatewayClient::new(
                gateway.clone(),
                Arc::new(client_tls),
                gp_proxy::gp::ResumptionPolicy::Memory {
                    tls12: rustls::client::Tls12Resumption::SessionIdOrTickets,
                },
            )
            .unwrap(),
            gateway.to_string(),
            task,
        )
    }

    #[tokio::test]
    async fn authenticated_configuration_failure_logs_out_but_keeps_status_until_shutdown() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (client, origin, gateway) = startup_gateway(Some("not XML")).await;
            let config = Config {
                gateway: origin,
                domains: vec!["corp.example".into()],
                http_listen: "127.0.0.1:0".parse().unwrap(),
                socks_listen: "127.0.0.1:0".parse().unwrap(),
                ..Config::default()
            };
            let session = Session::new(
                "test".into(),
                "test-cookie".into(),
                "test-portal".into(),
                "test-domain".into(),
                "test-computer".into(),
                None,
            )
            .unwrap();
            let server = bind_proxy(&config).await.unwrap();
            let addresses = server.local_addrs();
            let shutdown = CancellationToken::new();
            let work = serve_local(
                config,
                client.into(),
                Some(AuthInput::Session(session)),
                shutdown.clone(),
                server,
                None,
                None,
            );
            let check = async {
                // Terminal initial configuration failure cleans the cookie,
                // but the stable listener still answers a status request.
                gateway.await.unwrap();
                let status = gp_proxy::status::query(addresses.0).await.unwrap();
                assert!(!status.available);
                shutdown.cancel();
            };
            let (result, ()) = tokio::join!(work, check);
            result.unwrap();
            let _http = tokio::net::TcpListener::bind(addresses.0).await.unwrap();
            let _socks = tokio::net::TcpListener::bind(addresses.1).await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_authenticated_startup_logs_out_and_releases_reserved_listeners() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let config = Config {
                http_listen: "127.0.0.1:0".parse().unwrap(),
                socks_listen: "127.0.0.1:0".parse().unwrap(),
                ..Config::default()
            };
            let server = bind_proxy(&config).await.unwrap();
            let addresses = server.local_addrs();
            let session = Session::new(
                "test".into(),
                "test-cookie".into(),
                "test-portal".into(),
                "test-domain".into(),
                "test-computer".into(),
                None,
            )
            .unwrap();
            let (client, _, gateway) = startup_gateway(None).await;
            let shutdown = CancellationToken::new();
            shutdown.cancel();
            serve_local(
                config,
                client.into(),
                Some(AuthInput::Session(session)),
                shutdown,
                server,
                None,
                None,
            )
            .await
            .unwrap();
            gateway.await.unwrap();
            let _http = tokio::net::TcpListener::bind(addresses.0).await.unwrap();
            let _socks = tokio::net::TcpListener::bind(addresses.1).await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn imported_session_is_cleaned_when_local_service_setup_fails() {
        tokio::time::timeout(Duration::from_secs(10), async {
            for bad_policy in [true, false] {
                let (client, origin, gateway) = startup_gateway(None).await;
                let config = Config {
                    gateway: if bad_policy {
                        origin
                    } else {
                        "https://different.example.test".into()
                    },
                    domains: vec![if bad_policy {
                        "bad/domain"
                    } else {
                        "corp.example"
                    }
                    .into()],
                    http_listen: "127.0.0.1:0".parse().unwrap(),
                    socks_listen: "127.0.0.1:0".parse().unwrap(),
                    ..Config::default()
                };
                let server = bind_proxy(&config).await.unwrap();
                let addresses = server.local_addrs();
                let session = Session::new(
                    "test".into(),
                    "test-cookie".into(),
                    "portal".into(),
                    "domain".into(),
                    "computer".into(),
                    None,
                )
                .unwrap();
                assert!(serve_local(
                    config,
                    client.into(),
                    Some(AuthInput::Session(session)),
                    CancellationToken::new(),
                    server,
                    None,
                    None
                )
                .await
                .is_err());
                gateway.await.unwrap();
                let _http = tokio::net::TcpListener::bind(addresses.0).await.unwrap();
                let _socks = tokio::net::TcpListener::bind(addresses.1).await.unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[cfg(all(
        any(target_os = "macos", target_os = "linux"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    async fn damaged_control_endpoint_returns_error_and_releases_all_listeners() {
        use std::os::unix::fs::PermissionsExt;
        tokio::time::timeout(Duration::from_secs(10), async {
            let (client, origin, gateway) = startup_gateway(Some("not XML")).await;
            let config = Config {
                gateway: origin,
                domains: vec!["corp.example".into()],
                http_listen: "127.0.0.1:0".parse().unwrap(),
                socks_listen: "127.0.0.1:0".parse().unwrap(),
                ..Config::default()
            };
            let server = bind_proxy(&config).await.unwrap();
            let addresses = server.local_addrs();
            let directory = PathBuf::from("/tmp")
                .join(format!("gp-main-control-{:016x}", rand::random::<u64>()));
            let control = LocalListener::bind(&directory).unwrap();
            let session = Session::new(
                "test".into(),
                "test-cookie".into(),
                "portal".into(),
                "domain".into(),
                "computer".into(),
                None,
            )
            .unwrap();
            let work = serve_local(
                config,
                client.into(),
                Some(AuthInput::Session(session)),
                CancellationToken::new(),
                server,
                Some(control),
                None,
            );
            let damage = async {
                gateway.await.unwrap();
                std::fs::set_permissions(
                    directory.join("instance"),
                    std::fs::Permissions::from_mode(0o644),
                )
                .unwrap();
                // Wake the pending accept so its post-accept identity check
                // observes corruption. This contains no protocol or credentials.
                let _ = tokio::net::UnixStream::connect(directory.join("control.sock")).await;
            };
            let (result, ()) = tokio::join!(work, damage);
            assert!(
                result.is_err(),
                "control failure must not be hidden by shared shutdown"
            );
            let mut entries: Vec<_> = std::fs::read_dir(&directory)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            entries.sort();
            assert_eq!(entries, ["lock", "owner"]);
            std::fs::remove_dir_all(&directory).unwrap();
            let _http = tokio::net::TcpListener::bind(addresses.0).await.unwrap();
            let _socks = tokio::net::TcpListener::bind(addresses.1).await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn signal_error_cancels_and_waits_for_cleanup() {
        let shutdown = CancellationToken::new();
        let mut cleaned = false;
        let work = async {
            shutdown.cancelled().await;
            tokio::task::yield_now().await;
            cleaned = true;
            Ok(())
        };
        let signal = async { Err(io::Error::other("synthetic signal error")) };
        let result = drive_until_signal(&shutdown, work, signal).await;
        assert!(shutdown.is_cancelled());
        assert!(cleaned);
        assert!(result.is_err());
    }

    fn offline_client(origin: &str) -> GatewayClient {
        GatewayClient::new(
            url::Url::parse(origin).unwrap(),
            tls::client_config(None).unwrap(),
            gp_proxy::gp::ResumptionPolicy::Disabled,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn waiting_start_requires_control_and_releases_reserved_listeners() {
        let config = Config {
            gateway: "https://127.0.0.1:1".into(),
            domains: vec!["corp.example".into()],
            http_listen: "127.0.0.1:0".parse().unwrap(),
            socks_listen: "127.0.0.1:0".parse().unwrap(),
            ..Config::default()
        };
        let client = offline_client(&config.gateway);
        let server = bind_proxy(&config).await.unwrap();
        let addresses = server.local_addrs();
        let error = serve_local(
            config,
            client.into(),
            None,
            CancellationToken::new(),
            server,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::Unsupported
        );
        let _http = tokio::net::TcpListener::bind(addresses.0).await.unwrap();
        let _socks = tokio::net::TcpListener::bind(addresses.1).await.unwrap();
    }

    #[tokio::test]
    #[cfg(all(
        any(target_os = "macos", target_os = "linux"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    async fn waiting_start_serves_status_and_control_without_gateway_requests() {
        struct Directory(PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            let gateway = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            gateway.set_nonblocking(true).unwrap();
            let config = Config {
                gateway: format!("https://{}", gateway.local_addr().unwrap()),
                domains: vec!["corp.example".into()],
                http_listen: "127.0.0.1:0".parse().unwrap(),
                socks_listen: "127.0.0.1:0".parse().unwrap(),
                ..Config::default()
            };
            let client = offline_client(&config.gateway);
            let origin = config.gateway.clone();
            let server = bind_proxy(&config).await.unwrap();
            let addresses = server.local_addrs();
            let directory = Directory(
                PathBuf::from("/tmp").join(format!("gp-main-wait-{:016x}", rand::random::<u64>())),
            );
            let control = LocalListener::bind(&directory.0).unwrap();
            let shutdown = CancellationToken::new();
            let work = serve_local(
                config,
                client.into(),
                None,
                shutdown.clone(),
                server,
                Some(control),
                None,
            );
            let check = async {
                // The initial no-op task may complete; that must not terminate
                // the service or close its admission channel.
                for _ in 0..2 {
                    let preflight = control::preflight(&directory.0).await.unwrap();
                    assert!(preflight.matches_gateway(&origin));
                    let snapshot = gp_proxy::status::query(addresses.0).await.unwrap();
                    assert_eq!(snapshot.phase, gp_proxy::status::Phase::Stopped);
                    assert_eq!(
                        snapshot.reason,
                        gp_proxy::status::Reason::AuthenticationRequired
                    );
                    assert!(!snapshot.available);
                    assert_eq!(snapshot.retry_count, 0);
                    assert_eq!(
                        snapshot.active_tcp + snapshot.pending_tcp + snapshot.active_udp,
                        0
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert_eq!(
                    gateway.accept().unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                shutdown.cancel();
            };
            let (result, ()) = tokio::join!(work, check);
            result.unwrap();
            assert_eq!(
                gateway.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            let mut entries: Vec<_> = std::fs::read_dir(&directory.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            entries.sort();
            assert_eq!(entries, ["lock", "owner"]);
            let _http = tokio::net::TcpListener::bind(addresses.0).await.unwrap();
            let _socks = tokio::net::TcpListener::bind(addresses.1).await.unwrap();
        })
        .await
        .unwrap();
    }

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        let cli = Cli::try_parse_from(args)?;
        cli.validate_auth()?;
        Ok(cli)
    }

    #[test]
    fn disk_logging_is_run_only_and_size_requires_an_explicit_directory() {
        for bytes in ["65536", "4194304", "16777216"] {
            assert!(parse(&[
                "gp-proxy",
                "run",
                "--wait-auth",
                "--log-dir",
                "missing-logs",
                "--log-file-bytes",
                bytes,
            ])
            .is_ok());
        }
        assert!(parse(&[
            "gp-proxy",
            "run",
            "--wait-auth",
            "--log-dir",
            "missing-logs"
        ])
        .is_ok());
        for bytes in [
            "0",
            "65535",
            "16777217",
            "18446744073709551616",
            "not-a-size",
        ] {
            assert!(parse(&[
                "gp-proxy",
                "run",
                "--wait-auth",
                "--log-dir",
                "missing-logs",
                "--log-file-bytes",
                bytes,
            ])
            .is_err());
        }
        assert!(parse(&[
            "gp-proxy",
            "run",
            "--wait-auth",
            "--log-file-bytes",
            "65536"
        ])
        .is_err());
        for command in ["stop", "reauth", "status", "check", "pac", "probe"] {
            assert!(parse(&["gp-proxy", command, "--log-dir", "missing-logs"]).is_err());
        }
    }

    #[test]
    fn stop_rejects_credentials_and_validates_instance_before_io() {
        assert!(parse(&["gp-proxy", "stop"]).is_ok());
        let value = "00112233445566778899aAbBcCdDeEfF";
        let parsed = parse(&["gp-proxy", "stop", "--instance", value]).unwrap();
        assert!(
            matches!(parsed.command, Command::Stop { instance: Some(id) }
            if id == [0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        for option in ["--env-file", "--portal-env-file"] {
            assert!(parse(&["gp-proxy", option, "missing", "stop"]).is_err());
            assert!(parse(&["gp-proxy", "stop", option, "missing"]).is_err());
        }
        for value in [
            "",
            "0011",
            "00112233445566778899aabbccddeefg",
            "界界界界界界界界界界ab",
        ] {
            assert!(parse(&["gp-proxy", "stop", "--instance", value]).is_err());
        }
        for option in [
            "--username",
            "--session-file",
            "--password-stdin",
            "--interactive",
        ] {
            assert!(parse(&["gp-proxy", "stop", option]).is_err());
        }
    }

    #[test]
    fn interactive_flags_require_password_input_and_supported_terminal() {
        for command in ["run", "reauth"] {
            assert!(parse(&[
                "gp-proxy",
                command,
                "--interactive",
                "--session-file",
                "missing-session.json"
            ])
            .is_err());
            for arguments in [
                vec![
                    "gp-proxy",
                    command,
                    "--username",
                    "synthetic",
                    "--interactive",
                ],
                vec![
                    "gp-proxy",
                    command,
                    "--username",
                    "synthetic",
                    "--password-stdin",
                    "--interactive",
                ],
                vec![
                    "gp-proxy",
                    command,
                    "--env-file",
                    "missing-credentials",
                    "--interactive",
                ],
                vec![
                    "gp-proxy",
                    "--env-file",
                    "missing-credentials",
                    command,
                    "--interactive",
                ],
            ] {
                assert_eq!(parse(&arguments).is_ok(), terminal::supported());
            }
        }
        assert!(parse(&["gp-proxy", "run", "--wait-auth", "--interactive"]).is_err());
        assert!(parse(&["gp-proxy", "run", "--interactive"]).is_err());
        assert!(parse(&["gp-proxy", "reauth", "--interactive"]).is_err());
    }

    #[test]
    fn automation_sources_do_not_implicitly_enable_terminal_challenges() {
        assert!(!interaction_enabled(false, false, false));
        assert!(!interaction_enabled(true, true, false));
        assert_eq!(
            interaction_enabled(true, false, false),
            terminal::supported()
        );
        assert!(interaction_enabled(false, false, true));
        assert!(interaction_enabled(true, true, true));
    }

    #[tokio::test]
    async fn typed_terminal_interrupt_stops_work_but_other_input_errors_do_not() {
        for kind in [io::ErrorKind::Interrupted, io::ErrorKind::InvalidData] {
            let shutdown = CancellationToken::new();
            let result = cancellable_input(&shutdown, async {
                Err(io::Error::new(kind, "synthetic input failure"))
            })
            .await;
            assert_eq!(result.unwrap_err().kind(), kind);
            assert_eq!(shutdown.is_cancelled(), kind == io::ErrorKind::Interrupted);
        }
    }

    #[tokio::test]
    async fn shutdown_drops_active_input_before_returning() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Guard(Arc<AtomicBool>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let shutdown = CancellationToken::new();
        let (started, waiting) = tokio::sync::oneshot::channel();
        let input = async {
            let _guard = Guard(dropped.clone());
            started.send(()).unwrap();
            std::future::pending::<io::Result<Zeroizing<String>>>().await
        };
        let stop = async {
            waiting.await.unwrap();
            shutdown.cancel();
        };
        let (result, ()) = tokio::join!(cancellable_input(&shutdown, input), stop);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert!(dropped.load(Ordering::SeqCst));
        // Already-cancelled work must not start a new prompt.
        let result =
            cancellable_input(&shutdown, async { panic!("input must not be polled") }).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn wait_auth_requires_no_credential_source() {
        assert!(parse(&["gp-proxy", "run", "--wait-auth"]).is_ok());
        for arguments in [
            vec!["gp-proxy", "run", "--wait-auth", "--username", "synthetic"],
            vec!["gp-proxy", "run", "--wait-auth", "--password-stdin"],
            vec![
                "gp-proxy",
                "run",
                "--wait-auth",
                "--session-file",
                "missing-session.json",
            ],
            vec![
                "gp-proxy",
                "run",
                "--wait-auth",
                "--env-file",
                "missing-credentials",
            ],
            vec![
                "gp-proxy",
                "--env-file",
                "missing-credentials",
                "run",
                "--wait-auth",
            ],
            vec!["gp-proxy", "reauth", "--wait-auth"],
        ] {
            assert!(
                parse(&arguments).is_err(),
                "unexpectedly accepted {arguments:?}"
            );
        }
    }

    #[test]
    fn portal_credentials_are_explicit_and_conflicts_precede_file_access() {
        for command in ["run", "reauth"] {
            for arguments in [
                vec!["gp-proxy", "--portal-env-file", "missing-portal", command],
                vec!["gp-proxy", command, "--portal-env-file", "missing-portal"],
            ] {
                assert!(parse(&arguments).is_ok());
            }
            for arguments in [
                vec![
                    "gp-proxy",
                    "--env-file",
                    "missing-direct",
                    command,
                    "--portal-env-file",
                    "missing-portal",
                ],
                vec![
                    "gp-proxy",
                    "--portal-env-file",
                    "missing-portal",
                    command,
                    "--env-file",
                    "missing-direct",
                ],
                vec![
                    "gp-proxy",
                    command,
                    "--portal-env-file",
                    "missing-portal",
                    "--username",
                    "synthetic",
                ],
                vec![
                    "gp-proxy",
                    command,
                    "--portal-env-file",
                    "missing-portal",
                    "--session-file",
                    "missing-session",
                ],
            ] {
                assert!(parse(&arguments).is_err(), "{arguments:?}");
            }
        }
        assert!(parse(&[
            "gp-proxy",
            "run",
            "--wait-auth",
            "--portal-env-file",
            "missing"
        ])
        .is_err());
        assert!(parse(&[
            "gp-proxy",
            "--portal-env-file",
            "missing",
            "run",
            "--wait-auth"
        ])
        .is_err());
        assert!(parse(&["gp-proxy", "--portal-env-file", "missing", "probe"]).is_err());
        let binding =
            AuthBinding::via_portal("https://portal.example.test", "https://vpn.example.test")
                .unwrap();
        assert!(matches!(
            password_input(
                &binding,
                "user".into(),
                Zeroizing::new("password".into()),
                "host".into()
            ),
            AuthInput::PortalPassword { .. }
        ));
        assert!(matches!(
            password_authentication(
                &binding,
                Zeroizing::new("user".into()),
                Zeroizing::new("password".into()),
                "host".into()
            ),
            Authentication::PortalPassword { .. }
        ));
    }

    #[test]
    fn cli_requires_exactly_one_authentication_source() {
        assert!(parse(&["gp-proxy", "reauth"]).is_err());
        assert!(parse(&["gp-proxy", "reauth", "--username", "a", "--password-stdin"]).is_ok());
        assert!(parse(&["gp-proxy", "reauth", "--env-file", "synthetic.env"]).is_ok());
        assert!(parse(&[
            "gp-proxy",
            "reauth",
            "--username",
            "a",
            "--env-file",
            "synthetic.env"
        ])
        .is_err());
        assert!(parse(&["gp-proxy", "probe"]).is_err());
        assert!(parse(&["gp-proxy", "--env-file", "synthetic.env", "probe"]).is_ok());
        assert!(parse(&["gp-proxy", "run"]).is_err());
        assert!(parse(&["gp-proxy", "run", "--username", "a", "--session-file", "b"]).is_err());
        assert!(parse(&["gp-proxy", "run", "--username", "a"]).is_ok());
        assert!(parse(&["gp-proxy", "run", "--env-file", "synthetic.env"]).is_ok());
        assert!(parse(&["gp-proxy", "--env-file", "synthetic.env", "run"]).is_ok());
        assert!(parse(&[
            "gp-proxy",
            "run",
            "--env-file",
            "synthetic.env",
            "--username",
            "a"
        ])
        .is_err());
        assert!(parse(&[
            "gp-proxy",
            "run",
            "--env-file",
            "synthetic.env",
            "--session-file",
            "session.json"
        ])
        .is_err());
        assert!(parse(&[
            "gp-proxy",
            "run",
            "--env-file",
            "synthetic.env",
            "--password-stdin"
        ])
        .is_err());
    }
}
