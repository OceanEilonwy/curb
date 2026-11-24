pub mod astro_party;
pub mod halo_mcc;

use crate::MatchStateDetector;

/// Returns all compiled-in first-class per-title match-state plugins.
pub fn builtin_detectors() -> Vec<Box<dyn MatchStateDetector>> {
    vec![
        Box::new(halo_mcc::HaloMccDetector::new()),
        Box::new(astro_party::AstroPartyExDetector::new()),
    ]
}
