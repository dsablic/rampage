use std::collections::BTreeMap;

use rampage_arch::Target;
use rampage_loaders::Binary;

pub(super) fn mode_at(target: &Target, modes: &[(u64, bool)], address: u64) -> bool {
    modes
        .binary_search_by_key(&address, |&(address, _)| address)
        .ok()
        .map_or_else(|| target.is_thumb(address), |index| modes[index].1)
}

pub(super) fn arm_points(binary: &Binary, analysis_modes: &[(u64, bool)]) -> Vec<(u64, bool)> {
    let target = binary.target();
    let mut modes = BTreeMap::new();
    for segment in &binary.segments {
        if segment.perms.execute {
            modes.insert(segment.address, mode_at(&target, analysis_modes, segment.address));
        }
    }
    for range in target.thumb.iter() {
        modes.insert(range.start, true);
        modes.insert(range.end, target.is_thumb(range.end));
    }
    modes.extend(analysis_modes.iter().copied());
    // Equal-valued points are barriers: request-local mode changes must not overwrite other decoded runs.
    modes.into_iter().filter(|&(address, _)| address <= u64::from(u32::MAX)).collect()
}
