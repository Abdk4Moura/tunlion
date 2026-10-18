
## Mesh-disabled API boundary

With `default-features = false`, mesh policy and host ports are absent rather
than runtime stubs. These compile-fail examples run only in that configuration;
each independently checks one unavailable API while importing the common host.

```compile_fail,E0432
use filament_peerloop::mesh;
```

```compile_fail,E0599
use filament_peerloop::host::{HostServices, NoHost};
NoHost.hostname();
```

```compile_fail,E0599
use filament_peerloop::host::{HostServices, NoHost};
NoHost.overlay_identity();
```

```compile_fail,E0599
use filament_peerloop::host::{HostServices, NoHost};
NoHost.overlay_pubkey();
```

```compile_fail,E0599
use filament_peerloop::host::{HostServices, NoHost};
NoHost.overlay_sign_possession(b"proof");
```

```compile_fail,E0599
use filament_peerloop::host::{HostServices, NoHost};
// Inference is sufficient for the mode when the method exists; don't import
// the disabled mesh module here and accidentally test only that import.
NoHost.l3_start("fd00::1/128", 1280, None, todo!());
```
