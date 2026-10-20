//! Certificate-renewal policy, re-exported from the library.
//!
//! The mechanism moved to `filament_peerloop::recv::renewal` with the identity
//! store it consults. The names stay so every CLI call site resolves unchanged;
//! there is no second copy of the decision.

pub use filament_peerloop::recv::renewal::*;
