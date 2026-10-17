//! `blendr doctor` — Phase 0 diagnostics.
//!
//! Two distinct failure domains:
//!  * configuration errors (missing file, invalid JSON, failed validation)
//!  * missing platform prerequisites (system D-Bus, BlueZ, BLE controller,
//!    advertising capability)
//!
//! Each domain maps to its own exit code so scripts can tell "fix your
//! config.json" apart from "this machine has no usable Bluetooth". No
//! hardware addresses or other persistent identifiers are printed by
//! default: checks report counts, adapter sysfs names, and capabilities.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use blendr_config::Config;
use serde_json::Value;

/// Command-line usage errors (clap) already use code 2, so config and
/// prerequisite failures get dedicated codes below.
const EXIT_CONFIG_ERROR: u8 = 3;
const EXIT_PREREQ_ERROR: u8 = 4;

/// Upper bound on every external tool invocation. BlueZ / D-Bus tools can
/// hang when the bus or daemon is wedged; doctor must never block forever.
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// Grace period granted to pipe readers after the child has exited. A child
/// that leaks a pipe descriptor to a still-running grandchild postpones EOF
/// indefinitely; the drain wait must stay bounded so doctor keeps its hard
/// deadline. Whatever was captured before the grace lapses is kept.
const DRAIN_GRACE: Duration = Duration::from_millis(250);

/// Default per-connection system bus socket path (Linux).
const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";

#[derive(Clone, Copy)]
enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn marker(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

impl Check {
    fn new(name: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            name,
            status,
            detail: detail.into(),
        }
    }

    fn render(&self) -> String {
        format!("[{}] {}: {}", self.status.marker(), self.name, self.detail)
    }
}

pub(crate) fn run(config_path: &Path) -> ExitCode {
    let config = match load_config(config_path) {
        Ok(config) => config,
        Err(code) => return code,
    };

    let mut failed = false;

    println!("effective settings (config: {})", config_path.display());
    print_effective_settings(&config, config_path);

    println!();
    println!("platform prerequisites (linux/bluez):");
    let tools = Tools::detect();
    for check in linux_checks(&tools) {
        if matches!(check.status, Status::Fail) {
            failed = true;
        }
        println!("  {}", check.render());
    }

    println!();
    if failed {
        println!(
            "result: prerequisites missing — exit code {EXIT_PREREQ_ERROR} \
             (configuration itself is valid)"
        );
        ExitCode::from(EXIT_PREREQ_ERROR)
    } else {
        println!("result: ok — configuration valid, prerequisites satisfied or unverifiable");
        ExitCode::SUCCESS
    }
}

/// Load + validate the configuration. Config errors are reported verbatim
/// (they carry precise field paths from blendr-config) and map to their own
/// exit code so they are never confused with missing hardware.
fn load_config(config_path: &Path) -> Result<Config, ExitCode> {
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(err) => {
            report_config_error(config_path, &err);
            return Err(ExitCode::from(EXIT_CONFIG_ERROR));
        }
    };
    if let Err(err) = config.validate() {
        report_config_error(config_path, &err);
        return Err(ExitCode::from(EXIT_CONFIG_ERROR));
    }
    Ok(config)
}

fn report_config_error(config_path: &Path, err: &dyn std::error::Error) {
    let _ = writeln!(
        std::io::stderr(),
        "blendr doctor: configuration error in {}: {err}",
        config_path.display()
    );
}

/// Render non-secret settings. The config is serialized to a JSON value so
/// this stays decoupled from internal field types; keys are the same paths
/// used in `config.json`. Never prints key material, passphrases, or full
/// peer identifiers (none of those exist in the schema).
fn print_effective_settings(config: &Config, config_path: &Path) {
    let json = match serde_json::to_value(config) {
        Ok(value) => value,
        Err(err) => {
            println!("  <settings unavailable: {err}>");
            return;
        }
    };

    for key in SETTINGS_TO_SHOW {
        println!("  {key}: {}", render_scalar(at(&json, key)));
    }
    println!(
        "  derived.effective_outgoing_jumps: {}",
        config.effective_outgoing_jumps()
    );
    println!(
        "  derived.effective_incoming_jumps: {}",
        config.effective_incoming_jumps()
    );

    match Config::resolved_paths(config_path) {
        Ok(paths) => {
            println!("  resolved paths (relative to the config file):");
            for (label, path) in [
                ("data_dir", &paths.data_dir),
                ("keystore_path", &paths.keystore_path),
                ("database_path", &paths.database_path),
            ] {
                let note = if path.exists() {
                    "exists"
                } else {
                    "absent (created by `blendr init`)"
                };
                println!("    {label}: {} [{note}]", path.display());
            }
        }
        Err(err) => println!("  resolved paths: <unavailable: {err}>"),
    }
}

/// Non-secret keys worth surfacing. Deliberately excludes secret material
/// (none exists in the schema) and anything that could identify peers.
const SETTINGS_TO_SHOW: &[&str] = &[
    "config_version",
    "node.display_name",
    "node.mode",
    "node.start_discoverable",
    "identity.keystore_backend",
    "identity.display_bid_suffix_chars",
    "discovery.enabled",
    "discovery.advertise",
    "discovery.scan",
    "discovery.service_uuid",
    "discovery.scan_window_ms",
    "discovery.scan_interval_ms",
    "discovery.auto_connect",
    "transport.preferred",
    "transport.ble.adapter",
    "transport.ble.preferred_mtu",
    "transport.ble.max_frame_payload_bytes",
    "mesh.enabled",
    "mesh.outgoing.allow_jumps",
    "mesh.outgoing.max_jumps",
    "mesh.incoming.accept_relayed_messages",
    "mesh.incoming.max_jumps",
    "mesh.relay.enabled",
    "mesh.routing.strategy",
    "messaging.default_message_ttl_seconds",
    "messaging.sharing.default_visibility",
    "security.session_handshake",
    "security.asynchronous_message_encryption",
    "storage.engine",
    "storage.wal_enabled",
    "observability.log_level",
    "features.broadcast_mode",
    "features.direct_messages",
    "features.match_mode_v2",
    "features.wifi_transport",
    "features.internet_relay",
];

/// Look up a `a.b.c` JSON path inside a serialized config value.
fn at<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut node = root;
    for key in path.split('.') {
        node = node.get(key)?;
    }
    Some(node)
}

/// Render a JSON scalar without quotes; arrays/objects stay inline JSON.
fn render_scalar(value: Option<&Value>) -> String {
    match value {
        None => "<missing>".to_owned(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Linux prerequisite checks
// ---------------------------------------------------------------------------

fn linux_checks(tools: &Tools) -> Vec<Check> {
    vec![
        check_system_bus(tools),
        check_bluez_service(tools),
        check_controllers(tools),
        check_adapter_power(tools),
        check_le_advertising(tools),
        check_gatt_manager(tools),
        check_le_roles(tools),
    ]
}

/// 1. System D-Bus must exist and answer.
fn check_system_bus(tools: &Tools) -> Check {
    let name = "system D-Bus reachable";
    let mut attempts: Vec<String> = Vec::new();

    if tools.busctl {
        match run_bounded("busctl", &["--system", "list"], PROBE_TIMEOUT) {
            Probe::Finished(out) if out.status.success() => {
                return Check::new(name, Status::Pass, "system bus answers queries");
            }
            other => attempts.push(format!("busctl: {}", summarize(&other))),
        }
    }
    if tools.dbus_send {
        match run_bounded(
            "dbus-send",
            &[
                "--system",
                "--print-reply",
                "--dest=org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.Peer.Ping",
            ],
            PROBE_TIMEOUT,
        ) {
            Probe::Finished(out) if out.status.success() => {
                return Check::new(name, Status::Pass, "system bus answers queries");
            }
            other => attempts.push(format!("dbus-send: {}", summarize(&other))),
        }
    }

    if !tools.busctl && !tools.dbus_send {
        // No way to ask the bus anything; fall back to filesystem evidence.
        return if Path::new(SYSTEM_BUS_SOCKET).exists() {
            Check::new(
                name,
                Status::Warn,
                format!(
                    "socket {SYSTEM_BUS_SOCKET} present; install busctl or dbus-send to verify reachability"
                ),
            )
        } else {
            Check::new(
                name,
                Status::Fail,
                format!("no busctl/dbus-send tools and socket {SYSTEM_BUS_SOCKET} is absent"),
            )
        };
    }

    // Tools were present but every query failed; socket evidence still counts
    // as "bus daemon is probably up" but unresponsive → fail either way, the
    // detail explains which.
    let socket_note = if Path::new(SYSTEM_BUS_SOCKET).exists() {
        format!("socket {SYSTEM_BUS_SOCKET} exists but the bus did not answer")
    } else {
        format!("socket {SYSTEM_BUS_SOCKET} is absent")
    };
    Check::new(
        name,
        Status::Fail,
        format!("{socket_note} ({})", attempts.join("; ")),
    )
}

/// 2. The BlueZ daemon must own `org.bluez` on the system bus.
fn check_bluez_service(tools: &Tools) -> Check {
    let name = "BlueZ daemon (org.bluez)";
    let mut attempts: Vec<String> = Vec::new();

    if tools.busctl {
        match run_bounded(
            "busctl",
            &[
                "--system",
                "call",
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "NameHasOwner",
                "s",
                "org.bluez",
            ],
            PROBE_TIMEOUT,
        ) {
            Probe::Finished(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains("true") {
                    return Check::new(
                        name,
                        Status::Pass,
                        bluez_version_note(tools, "registered on system bus"),
                    );
                }
                return Check::new(
                    name,
                    Status::Fail,
                    "org.bluez has no owner — start/enable the bluetooth service (e.g. `systemctl start bluetooth`)",
                );
            }
            other => attempts.push(format!("busctl: {}", summarize(&other))),
        }
    }
    if tools.dbus_send {
        match run_bounded(
            "dbus-send",
            &[
                "--system",
                "--print-reply",
                "--dest=org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.NameHasOwner",
                "string:org.bluez",
            ],
            PROBE_TIMEOUT,
        ) {
            Probe::Finished(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains("true") {
                    return Check::new(
                        name,
                        Status::Pass,
                        bluez_version_note(tools, "registered on system bus"),
                    );
                }
                return Check::new(
                    name,
                    Status::Fail,
                    "org.bluez has no owner — start/enable the bluetooth service",
                );
            }
            other => attempts.push(format!("dbus-send: {}", summarize(&other))),
        }
    }
    if tools.bluetoothctl && attempts.is_empty() {
        match run_bounded("bluetoothctl", &["list"], PROBE_TIMEOUT) {
            Probe::Finished(out) if out.status.success() => {
                return Check::new(
                    name,
                    Status::Pass,
                    bluez_version_note(tools, "responds via bluetoothctl"),
                );
            }
            other => attempts.push(format!("bluetoothctl: {}", summarize(&other))),
        }
    }

    if attempts.is_empty() {
        return Check::new(
            name,
            Status::Warn,
            "cannot verify: install busctl, dbus-send, or bluetoothctl",
        );
    }
    Check::new(
        name,
        Status::Fail,
        format!("org.bluez unreachable ({})", attempts.join("; ")),
    )
}

/// `bluetoothctl --version` reports the BlueZ release; purely informational.
fn bluez_version_note(tools: &Tools, base: &str) -> String {
    if !tools.bluetoothctl {
        return base.to_owned();
    }
    if let Probe::Finished(out) = run_bounded("bluetoothctl", &["--version"], PROBE_TIMEOUT)
        && out.status.success()
    {
        let version = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !version.is_empty() {
            return format!("{base}; {version}");
        }
    }
    base.to_owned()
}

/// 3. At least one BLE controller must exist. sysfs is authoritative for the
///    kernel-visible adapters; busctl enumerates what BlueZ actually claims.
fn check_controllers(tools: &Tools) -> Check {
    let name = "BLE controller present";

    let bus_adapters = busctl_adapters(tools);
    let mut adapters = sysfs_adapters();
    adapters.extend(bus_adapters.iter().cloned());
    adapters.sort();
    adapters.dedup();

    if adapters.is_empty() {
        let detail = if tools.busctl {
            "no controllers in /sys/class/bluetooth and none reported by BlueZ — no usable Bluetooth adapter"
        } else {
            "no controllers in /sys/class/bluetooth (BlueZ not queried: busctl unavailable)"
        };
        return Check::new(name, Status::Fail, detail);
    }

    let mut detail = format!("{} controller(s): {}", adapters.len(), adapters.join(", "));

    if tools.busctl && bus_adapters.is_empty() {
        detail.push_str("; BlueZ claims none — check bluetoothd/systemd unit");
    }
    Check::new(name, Status::Pass, detail)
}

/// 4. Every discovered controller must be powered on (not rfkill-blocked).
fn check_adapter_power(tools: &Tools) -> Check {
    let name = "adapter powered";
    let adapters = merged_adapter_list(tools);
    if adapters.is_empty() {
        return Check::new(
            name,
            Status::Warn,
            "no adapter to check (see controller check)",
        );
    }

    let single_adapter = adapters.len() == 1;
    let mut failed: Vec<String> = Vec::new();
    let mut unverified: Vec<String> = Vec::new();
    for adapter in &adapters {
        match adapter_powered(tools, adapter, single_adapter) {
            Some(true) => {}
            Some(false) => failed.push(format!("{adapter} is powered off or blocked (try `rfkill unblock bluetooth`, `bluetoothctl power on`)")),
            None => unverified.push(adapter.clone()),
        }
    }

    if !failed.is_empty() {
        return Check::new(name, Status::Fail, failed.join("; "));
    }
    if !unverified.is_empty() {
        return Check::new(
            name,
            Status::Warn,
            format!(
                "power state unverified for {} (need busctl or bluetoothctl)",
                unverified.join(", ")
            ),
        );
    }
    Check::new(name, Status::Pass, "all controllers powered on")
}

/// 5. Advertising requires org.bluez.LEAdvertisingManager1.
fn check_le_advertising(tools: &Tools) -> Check {
    let mut check = check_interface(
        tools,
        "LE advertising supported",
        "org.bluez.LEAdvertisingManager1",
        "LEAdvertisingManager1 absent — controller/driver/BlueZ lacks peripheral advertising; Blendr cannot advertise",
    );
    // When verifiable, also report the controller's advertising instance
    // budget — some adapters support only a handful of concurrent instances.
    if matches!(check.status, Status::Pass) {
        let counts: Vec<String> = merged_adapter_list(tools)
            .iter()
            .filter_map(|adapter| {
                let object = format!("/org/bluez/{adapter}");
                get_property_raw(
                    &object,
                    "org.bluez.LEAdvertisingManager1",
                    "SupportedInstances",
                )
                .and_then(|raw| raw.split_whitespace().last().map(str::to_string))
                .map(|n| format!("{adapter}: {n} advertisement instance(s)"))
            })
            .collect();
        if !counts.is_empty() {
            check.detail = format!("{} ({})", check.detail, counts.join(", "));
        }
    }
    check
}

/// 6. GATT server requires org.bluez.GattManager1.
fn check_gatt_manager(tools: &Tools) -> Check {
    check_interface(
        tools,
        "GATT server supported",
        "org.bluez.GattManager1",
        "GattManager1 absent — BlueZ cannot register a local GATT service",
    )
}

fn check_interface(tools: &Tools, name: &'static str, interface: &str, fail_detail: &str) -> Check {
    let adapters = merged_adapter_list(tools);
    if adapters.is_empty() {
        return Check::new(
            name,
            Status::Warn,
            "no adapter to check (see controller check)",
        );
    }
    if !tools.busctl {
        return Check::new(
            name,
            Status::Warn,
            "unverified: busctl not installed (filesystem checks cannot see BlueZ capabilities)",
        );
    }

    // BlueZ only exposes these interfaces when the controller supports the
    // feature, so a successful introspection proves capability. Note
    // GattManager1 has no SupportedInstances property — introspection is the
    // portable probe for both.
    let mut failed = Vec::new();
    for adapter in &adapters {
        let object = format!("/org/bluez/{adapter}");
        match run_bounded(
            "busctl",
            &["--system", "introspect", "org.bluez", &object, interface],
            PROBE_TIMEOUT,
        ) {
            Probe::Finished(out) if out.status.success() => {}
            other => failed.push(format!("{adapter}: {}", summarize(&other))),
        }
    }
    if failed.is_empty() {
        Check::new(
            name,
            Status::Pass,
            format!("{interface} present on all controllers"),
        )
    } else {
        Check::new(
            name,
            Status::Fail,
            format!("{fail_detail} ({})", failed.join("; ")),
        )
    }
}

/// 7. Controller must support both central and peripheral LE roles
///    (Blendr scans and advertises).
fn check_le_roles(tools: &Tools) -> Check {
    let name = "LE roles (central + peripheral)";
    let adapters = merged_adapter_list(tools);
    if adapters.is_empty() {
        return Check::new(
            name,
            Status::Warn,
            "no adapter to check (see controller check)",
        );
    }

    let single_adapter = adapters.len() == 1;
    let mut unverified: Vec<String> = Vec::new();
    for adapter in &adapters {
        match adapter_roles(tools, adapter, single_adapter) {
            Some(roles) => {
                if !(roles.contains("central") && roles.contains("peripheral")) {
                    return Check::new(
                        name,
                        Status::Fail,
                        format!(
                            "{adapter} reports roles \"{roles}\"; Blendr needs central+peripheral"
                        ),
                    );
                }
            }
            None => unverified.push(adapter.clone()),
        }
    }
    if !unverified.is_empty() {
        return Check::new(
            name,
            Status::Warn,
            format!(
                "roles unverified for {} (need busctl or bluetoothctl)",
                unverified.join(", ")
            ),
        );
    }
    Check::new(name, Status::Pass, "central+peripheral on all controllers")
}

/// Controller LE roles: Adapter1 `SupportedRoles`/`Roles` via D-Bus, or the
/// `Roles:` line of `bluetoothctl show` on single-adapter hosts.
fn adapter_roles(tools: &Tools, adapter: &str, single_adapter: bool) -> Option<String> {
    let object = format!("/org/bluez/{adapter}");
    if tools.busctl {
        for property in ["SupportedRoles", "Roles"] {
            if let Some(roles) = get_property_string(&object, "org.bluez.Adapter1", property) {
                return Some(roles);
            }
        }
    }
    // `bluetoothctl show` only describes the default controller, so it is
    // only meaningful when exactly one controller exists.
    if tools.bluetoothctl && single_adapter {
        return bluetoothctl_field("Roles:");
    }
    None
}

// ---------------------------------------------------------------------------
// Adapter enumeration helpers
// ---------------------------------------------------------------------------

/// Controller names exclude HCI connection entries such as `hci0:256`.
fn is_adapter_name(name: &str) -> bool {
    name.strip_prefix("hci")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
}

/// Kernel-visible controllers: only `/sys/class/bluetooth/hciN` entries.
fn sysfs_adapters() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/bluetooth") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && is_adapter_name(name)
            {
                out.push(name.to_owned());
            }
        }
    }
    out
}

/// BlueZ-visible controllers via ObjectManager.GetManagedObjects.
fn busctl_adapters(tools: &Tools) -> Vec<String> {
    if !tools.busctl {
        return Vec::new();
    }
    let out = match run_bounded(
        "busctl",
        &[
            "--system",
            "call",
            "org.bluez",
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "GetManagedObjects",
        ],
        PROBE_TIMEOUT,
    ) {
        Probe::Finished(out) if out.status.success() => out,
        _ => return Vec::new(),
    };
    parse_adapter_paths(&String::from_utf8_lossy(&out.stdout))
}

/// Extract `hciN` tokens from `/org/bluez/hciN` object paths in busctl output.
fn parse_adapter_paths(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in text.split(['"', ' ', '\t', '\n']) {
        if let Some(rest) = token.strip_prefix("/org/bluez/") {
            let name = rest.split('/').next().unwrap_or_default();
            if is_adapter_name(name) {
                out.push(name.to_owned());
            }
        }
    }
    out
}

/// Union of sysfs and BlueZ-reported adapter names.
fn merged_adapter_list(tools: &Tools) -> Vec<String> {
    let mut adapters = sysfs_adapters();
    adapters.extend(busctl_adapters(tools));
    adapters.sort();
    adapters.dedup();
    adapters
}

/// Read an Adapter1 boolean/string property; None = could not determine.
fn adapter_powered(tools: &Tools, adapter: &str, single_adapter: bool) -> Option<bool> {
    let object = format!("/org/bluez/{adapter}");
    if tools.busctl
        && let Some(text) = get_property_raw(&object, "org.bluez.Adapter1", "Powered")
    {
        return Some(text.contains("true"));
    }
    // rfkill evidence is adapter-agnostic: a blocked radio disables every
    // controller. Only a *blocked* result is conclusive here.
    if bluetooth_rfkill_blocked() == Some(true) {
        return Some(false);
    }
    // `bluetoothctl show` only describes the default controller.
    if tools.bluetoothctl
        && single_adapter
        && let Some(value) = bluetoothctl_field("Powered:")
    {
        return Some(value.eq_ignore_ascii_case("yes"));
    }
    None
}

/// Extract a "Key: value" field from `bluetoothctl show` (default adapter).
fn bluetoothctl_field(prefix: &str) -> Option<String> {
    let out = match run_bounded("bluetoothctl", &["show"], PROBE_TIMEOUT) {
        Probe::Finished(out) if out.status.success() => out,
        _ => return None,
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(prefix) {
            return Some(rest.trim().to_owned());
        }
    }
    None
}

/// Is any bluetooth rfkill device blocked? None = no bluetooth rfkill
/// entries exist, so the kernel cannot tell us either way.
fn bluetooth_rfkill_blocked() -> Option<bool> {
    let entries = std::fs::read_dir("/sys/class/rfkill").ok()?;
    let mut found_any = false;
    for entry in entries.flatten() {
        let dir = entry.path();
        let kind = std::fs::read_to_string(dir.join("type")).unwrap_or_default();
        if kind.trim() != "bluetooth" {
            continue;
        }
        found_any = true;
        let soft = std::fs::read_to_string(dir.join("soft")).unwrap_or_default();
        let hard = std::fs::read_to_string(dir.join("hard")).unwrap_or_default();
        if soft.trim() == "1" || hard.trim() == "1" {
            return Some(true);
        }
    }
    found_any.then_some(false)
}

/// Get a BlueZ property as raw busctl output text.
fn get_property_raw(object: &str, interface: &str, property: &str) -> Option<String> {
    let out = match run_bounded(
        "busctl",
        &[
            "--system",
            "call",
            "org.bluez",
            object,
            "org.freedesktop.DBus.Properties",
            "Get",
            "ss",
            interface,
            property,
        ],
        PROBE_TIMEOUT,
    ) {
        Probe::Finished(out) if out.status.success() => out,
        _ => return None,
    };
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Read a string-valued property and return the first quoted payload or the
/// whitespace-separated value token.
fn get_property_string(object: &str, interface: &str, property: &str) -> Option<String> {
    let raw = get_property_raw(object, interface, property)?;
    // busctl renders variants like `as 2 "central" "peripheral"` or
    // `s "central peripheral"`. Collect quoted tokens first.
    let quoted: Vec<String> = raw
        .split('"')
        .skip(1)
        .step_by(2)
        .map(String::from)
        .collect();
    if !quoted.is_empty() {
        return Some(quoted.join(" "));
    }
    Some(raw)
}

// ---------------------------------------------------------------------------
// Bounded subprocess execution
// ---------------------------------------------------------------------------

/// External tools whose presence/absence shapes how much doctor can verify.
struct Tools {
    busctl: bool,
    dbus_send: bool,
    bluetoothctl: bool,
}

impl Tools {
    fn detect() -> Self {
        Self {
            busctl: tool_exists("busctl"),
            dbus_send: tool_exists("dbus-send"),
            bluetoothctl: tool_exists("bluetoothctl"),
        }
    }
}

fn tool_exists(tool: &str) -> bool {
    match run_bounded(tool, &[OsStr::new("--version")], Duration::from_secs(1)) {
        Probe::Finished(_) => true,
        Probe::SpawnFailed(_) | Probe::TimedOut => false,
    }
}

enum Probe {
    Finished(std::process::Output),
    TimedOut,
    SpawnFailed(std::io::Error),
}

/// Run `argv` capturing stdout/stderr with a hard deadline; kills the child
/// on timeout so doctor can never hang on a wedged daemon. Pipe drains are
/// bounded by `DRAIN_GRACE` in case a descendant inherits a pipe descriptor.
fn run_bounded<S>(argv0: &str, argv_rest: &[S], timeout: Duration) -> Probe
where
    S: AsRef<OsStr>,
{
    let mut child = match Command::new(argv0)
        .args(argv_rest)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => return Probe::SpawnFailed(err),
    };

    // Drain pipes on threads so a verbose child cannot deadlock on a full
    // pipe. Buffers are shared so partially read output is still captured
    // when a leaked descriptor keeps a reader alive past DRAIN_GRACE.
    let stdout_drain = spawn_drain(child.stdout.take());
    let stderr_drain = spawn_drain(child.stderr.take());

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let mut status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break None,
        }
    };
    if status.is_none() {
        // Reap the (possibly killed) child so the reader threads can finish.
        status = child.wait().ok();
    }
    let stdout = collect_drain(stdout_drain);
    let stderr = collect_drain(stderr_drain);

    if timed_out {
        return Probe::TimedOut;
    }
    match status {
        Some(status) => Probe::Finished(std::process::Output {
            status,
            stdout,
            stderr,
        }),
        None => Probe::TimedOut,
    }
}

/// Shared state between a pipe reader thread and `run_bounded`.
struct Drain {
    /// Everything read so far; valid even if the thread is abandoned.
    buf: Arc<Mutex<Vec<u8>>>,
    /// Receives `()` once the pipe reaches EOF and the thread exits.
    done: mpsc::Receiver<()>,
}

/// Read `pipe` to EOF on a detached thread, filling a shared buffer.
fn spawn_drain<R>(pipe: Option<R>) -> Drain
where
    R: Read + Send + 'static,
{
    let buf = Arc::new(Mutex::new(Vec::new()));
    let (tx, done) = mpsc::channel();
    let thread_buf = Arc::clone(&buf);
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        if let Some(mut pipe) = pipe {
            while let Ok(n) = pipe.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let mut buf = thread_buf.lock().unwrap_or_else(PoisonError::into_inner);
                buf.extend_from_slice(&chunk[..n]);
            }
        }
        let _ = tx.send(());
    });
    Drain { buf, done }
}

/// Collect a drained pipe's bytes. Returns whatever was captured if the
/// reader is still blocked (a descendant is holding the write end open);
/// the detached thread exits harmlessly once that descriptor closes.
fn collect_drain(drain: Drain) -> Vec<u8> {
    let _ = drain.done.recv_timeout(DRAIN_GRACE);
    std::mem::take(&mut drain.buf.lock().unwrap_or_else(PoisonError::into_inner))
}

fn summarize(probe: &Probe) -> String {
    match probe {
        Probe::SpawnFailed(err) if err.kind() == std::io::ErrorKind::NotFound => {
            "tool not installed".to_owned()
        }
        Probe::SpawnFailed(err) => format!("spawn failed: {err}"),
        Probe::TimedOut => format!("timed out after {}s", PROBE_TIMEOUT.as_secs()),
        Probe::Finished(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let detail = stderr
                .lines()
                .chain(stdout.lines())
                .find(|l| !l.trim().is_empty())
                .unwrap_or("no output");
            format!("exit {}: {}", out.status, detail.trim())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{is_adapter_name, parse_adapter_paths};

    #[test]
    fn only_numbered_hci_controllers_are_adapters() {
        for controller in ["hci0", "hci1", "hci12", "hci256"] {
            assert!(is_adapter_name(controller), "{controller}");
        }
        for other in [
            "hci0:256",
            "hci1:512",
            "hci",
            "hci-1",
            "hci0_extra",
            "hci０",
            "hci0/device",
            "rfkill0",
        ] {
            assert!(!is_adapter_name(other), "{other}");
        }
    }

    #[test]
    fn bluez_paths_reject_connection_entries_without_truncating_them() {
        let objects = r#""/org/bluez/hci0" "/org/bluez/hci12/dev_00_11_22_33_44_55" "/org/bluez/hci0:256" "/org/bluez/hci1_extra" "/org/bluez/hci""#;
        assert_eq!(parse_adapter_paths(objects), ["hci0", "hci12"]);
    }
}
