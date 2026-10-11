use rampage_api::{BranchSlotStatus, PointerAssessment, Project};
use rampage_arch::Flow;
use rampage_loaders::Binary;

struct Fixture(std::path::PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-branch-observation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn project(&self, words: &[u32], value: u64, permissions: &str) -> Project {
        self.project_at(words, value, permissions, 0x1000, 0x3000)
    }

    fn project_at(&self, words: &[u32], value: u64, permissions: &str, start: u64, slot: u64) -> Project {
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let snapshot = serde_json::json!({"format": "rampage-snapshot-v1", "arch": "aarch64", "entry": null,
            "provenance": "controlled branch-slot fixture", "regions": [
                {"name": "window", "address": format!("{start:#x}"), "permissions": "r-x",
                    "bytes": rampage_arch::hex::bytes(&bytes)},
                {"name": "slot", "address": format!("{slot:#x}"), "permissions": permissions,
                    "bytes": rampage_arch::hex::bytes(&value.to_le_bytes())},
                {"name": "target", "address": "0x5000", "permissions": "r-x", "bytes": "c0035fd6"}]});
        let path = self.0.join("snapshot.json");
        std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        Project::new(Binary::open(path).unwrap())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn address_load_move_branch_links_writable_slot_without_resolving_flow() {
    let fixture = Fixture::new();
    for branch in [0xd61f_0120, 0xd63f_0120] {
        let project = fixture.project(&[0xd000_0008, 0xf940_0108, 0xaa08_03e9, branch], 0x5000, "rw-");
        let result = project.observe_indirect_branch(0x1000, 0x100c).unwrap();
        assert_eq!(result.slot_status, BranchSlotStatus::Linked);
        assert_eq!(result.load_address, Some(0x1004));
        assert_eq!(result.flow, if branch == 0xd61f_0120 { Flow::IndirectJump } else { Flow::IndirectCall });
        let pointer = result.pointer.unwrap();
        assert_eq!(pointer.slot, 0x3000);
        assert_eq!(pointer.raw_value, Some(0x5000));
        assert_eq!(pointer.candidate_target, Some(0x5000));
        assert!(pointer.slot_permissions.unwrap().write);
        assert!(project.binary.read_pointer(0x3000, 8).is_none());
        assert!(project.annotation_list().names.is_empty());
    }
}

#[test]
fn signed_adr_and_literal_loads_and_add_offsets_form_exact_slots() {
    let fixture = Fixture::new();
    for words in [
        vec![0x1001_0008, 0xf940_0108, 0xd61f_0100],
        vec![0x5801_0008, 0xd61f_0100],
        vec![0xd000_0008, 0x9100_0108, 0xf940_0108, 0xd61f_0100],
    ] {
        let project = fixture.project(&words, 0x5000, "r--");
        let result = project.observe_indirect_branch(0x1000, 0x1000 + (words.len() as u64 - 1) * 4).unwrap();
        assert_eq!(result.slot_status, BranchSlotStatus::Linked);
        assert_eq!(result.pointer.unwrap().slot, 0x3000);
    }
}

#[test]
fn control_flow_stores_and_unsupported_writes_stop_linking() {
    let fixture = Fixture::new();
    for (word, status) in [
        (0x9400_0000, BranchSlotStatus::ControlFlowBoundary),
        (0x5400_0000, BranchSlotStatus::ControlFlowBoundary),
        (0xf900_0108, BranchSlotStatus::UnsupportedInstruction),
        (0xd280_0008, BranchSlotStatus::UnsupportedInstruction),
    ] {
        let project = fixture.project(&[0xd000_0008, 0xf940_0108, word, 0xd61f_0100], 0x5000, "rw-");
        let result = project.observe_indirect_branch(0x1000, 0x100c).unwrap();
        assert_eq!(result.slot_status, status);
        assert_eq!(result.evidence_stopped_at, Some(0x1008));
        assert!(result.pointer.is_none());
    }
}

#[test]
fn overwritten_wrong_register_and_unavailable_slots_do_not_invent_values() {
    let fixture = Fixture::new();
    for words in [vec![0xd000_0008, 0xf940_0108, 0x1000_0008, 0xd61f_0100], vec![0xd000_0008, 0xf940_0108, 0xd61f_0120]]
    {
        let project = fixture.project(&words, 0x5000, "rw-");
        let result = project.observe_indirect_branch(0x1000, 0x1000 + (words.len() as u64 - 1) * 4).unwrap();
        assert_eq!(result.slot_status, BranchSlotStatus::NoSlotEvidence);
        assert!(result.pointer.is_none());
    }
    let project = fixture.project(&[0xd000_0008, 0xf940_0108, 0xd61f_0100], 0x5000, "-w-");
    let result = project.observe_indirect_branch(0x1000, 0x1008).unwrap();
    assert_eq!(result.slot_status, BranchSlotStatus::Linked);
    let pointer = result.pointer.unwrap();
    assert_eq!(pointer.assessment, PointerAssessment::Unavailable);
    assert!(pointer.raw_value.is_none());
}

#[test]
fn window_limits_missing_backing_and_authentication_remain_explicit() {
    let fixture = Fixture::new();
    let mut project = fixture.project(&[0xd000_0008, 0xf940_0108, 0xd61f_0100], 0x5000, "rw-");
    for (start, branch) in [(0x1001, 0x1008), (0x100c, 0x1008), (0x1000, 0x1100), (0x1000, 0x1004)] {
        assert!(project.observe_indirect_branch(start, branch).is_err());
    }
    project.binary.segments[0].perms.read = false;
    assert!(project.observe_indirect_branch(0x1000, 0x1008).is_err());
    let project = fixture.project(&[0xd000_0008, 0xf940_0108, 0xd61f_0100], 0x5000, "rw-");
    let result = project.observe_indirect_branch(0xffc, 0x1008).unwrap();
    assert_eq!(result.slot_status, BranchSlotStatus::IncompleteWindow);
    assert!(result.pointer.is_none());
    let project = fixture.project(&[0xd000_0008, 0xf940_0108, 0xd71f_0900], 0x5000, "rw-");
    let result = project.observe_indirect_branch(0x1000, 0x1008).unwrap();
    assert_eq!(result.slot_status, BranchSlotStatus::AuthenticatedBranch);
    assert!(result.pointer.is_none());
}

#[test]
fn identity_adds_preserve_slot_evidence_and_sp_does_not_alias_xzr() {
    let fixture = Fixture::new();
    for (words, slot) in [
        (vec![0xd000_0008, 0xf940_0108, 0x9100_0109, 0xd61f_0120], Some(0x3000)),
        (vec![0xd000_0008, 0x9100_011f, 0xf940_03e9, 0xd61f_0120], Some(0x3000)),
        (vec![0xd000_0008, 0x9100_011f, 0xaa1f_03e9, 0xf940_0129, 0xd61f_0120], Some(0)),
    ] {
        let project = fixture.project(&words, 0x5000, "rw-");
        let result = project.observe_indirect_branch(0x1000, 0x1000 + (words.len() as u64 - 1) * 4).unwrap();
        assert_eq!(result.pointer.map(|pointer| pointer.slot), slot);
    }
}

#[test]
fn zero_register_address_formation_is_known_without_incoming_register_evidence() {
    let fixture = Fixture::new();
    let project =
        fixture.project_at(&[0xaa1f_03e9, 0x910c_0129, 0xf940_012a, 0xd61f_0140], 0x5000, "rw-", 0x1000, 0x300);
    let result = project.observe_indirect_branch(0x1000, 0x100c).unwrap();
    assert_eq!(result.slot_status, BranchSlotStatus::Linked);
    assert_eq!(result.pointer.unwrap().slot, 0x300);
}

#[test]
fn signed_address_formation_uses_architectural_wrapping_arithmetic() {
    let fixture = Fixture::new();
    for words in [
        vec![0x10ff_0008, 0xf940_0108, 0xd61f_0100],
        vec![0xd0ff_ffe8, 0xf940_0108, 0xd61f_0100],
        vec![0x58ff_0008, 0xd61f_0100],
    ] {
        let project = fixture.project_at(&words, 0x5000, "r--", 0x1000, 0xffff_ffff_ffff_f000);
        let result = project.observe_indirect_branch(0x1000, 0x1000 + (words.len() as u64 - 1) * 4).unwrap();
        assert_eq!(result.slot_status, BranchSlotStatus::Linked);
        assert_eq!(result.pointer.unwrap().slot, 0xffff_ffff_ffff_f000);
    }
}
