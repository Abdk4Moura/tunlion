//! Single-binary consolidation for standalone CLI integration tests.
//!
//! Compiling 18 separate integration binaries linked 18 copies of tokio,
//! webrtc, quinn, ring, reqwest, and clap on every test build. Keeping them as
//! modules in one integration crate cuts 18 links down to 1 while running the
//! exact same tests (`cargo test --test cli_integration <mod>::`).

#[path = "cli_integration/access_bootstrap.rs"]
mod access_bootstrap;
#[path = "cli_integration/arm_mechanism_tests.rs"]
mod arm_mechanism_tests;
#[path = "cli_integration/caps_display_tests.rs"]
mod caps_display_tests;
#[path = "cli_integration/daemon_identity_tests.rs"]
mod daemon_identity_tests;
#[path = "cli_integration/devices_status_tests.rs"]
mod devices_status_tests;
#[path = "cli_integration/home_env_guard.rs"]
mod home_env_guard;
#[path = "cli_integration/init_inbox_cli.rs"]
mod init_inbox_cli;
#[path = "cli_integration/l3_state_cli.rs"]
mod l3_state_cli;
#[path = "cli_integration/man_install_tests.rs"]
mod man_install_tests;
#[path = "cli_integration/man_tests.rs"]
mod man_tests;
#[path = "cli_integration/proxy_http_pac_tests.rs"]
mod proxy_http_pac_tests;
#[path = "cli_integration/set_contract.rs"]
mod set_contract;
#[path = "cli_integration/surface_output.rs"]
mod surface_output;
#[path = "cli_integration/surface_platform.rs"]
mod surface_platform;
#[path = "cli_integration/surface_spawn.rs"]
mod surface_spawn;
#[path = "cli_integration/timeout_tests.rs"]
mod timeout_tests;
#[path = "cli_integration/warm_one_shot_tests.rs"]
mod warm_one_shot_tests;
#[path = "cli_integration/warm_pty_tests.rs"]
mod warm_pty_tests;
