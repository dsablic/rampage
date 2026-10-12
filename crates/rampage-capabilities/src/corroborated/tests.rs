use crate::{Capability, detect};

struct Case {
    id: &'static str,
    imports: &'static [&'static str],
    strings: &'static [&'static str],
    benign_imports: &'static [&'static str],
    benign_strings: &'static [&'static str],
}

const CASES: &[Case] = &[
    Case {
        id: "persistence-registry-run",
        imports: &["RegCreateKeyExW", "RegSetValueExW"],
        strings: &["HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
        benign_imports: &["RegOpenKeyExW", "RegQueryValueExW"],
        benign_strings: &["Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
    },
    Case {
        id: "persistence-scheduled-task",
        imports: &["CoCreateInstance"],
        strings: &["Schedule.Service", "ITaskFolder::RegisterTaskDefinition"],
        benign_imports: &["CoCreateInstance", "CoInitializeEx"],
        benign_strings: &["ITaskService", "ITaskFolder::GetTasks"],
    },
    Case {
        id: "persistence-service-install",
        imports: &["OpenSCManagerW", "CreateServiceW"],
        strings: &[],
        benign_imports: &["OpenSCManagerW", "OpenServiceW", "QueryServiceStatusEx"],
        benign_strings: &[],
    },
    Case {
        id: "process-enumeration",
        imports: &["CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW"],
        strings: &[],
        benign_imports: &["CreateToolhelp32Snapshot", "Module32FirstW", "Module32NextW"],
        benign_strings: &[],
    },
    Case {
        id: "token-privilege",
        imports: &["OpenProcessToken", "LookupPrivilegeValueW", "AdjustTokenPrivileges"],
        strings: &[],
        benign_imports: &["OpenProcessToken", "GetTokenInformation", "LookupPrivilegeValueW"],
        benign_strings: &[],
    },
    Case {
        id: "debug-privilege",
        imports: &["OpenThreadToken", "LookupPrivilegeValueA", "AdjustTokenPrivileges"],
        strings: &["SeDebugPrivilege"],
        benign_imports: &["OpenProcessToken", "LookupPrivilegeValueW", "AdjustTokenPrivileges"],
        benign_strings: &["SeChangeNotifyPrivilege"],
    },
    Case {
        id: "screen-capture",
        imports: &["GetDC", "CreateCompatibleDC", "CreateCompatibleBitmap", "BitBlt", "GetDIBits"],
        strings: &[],
        benign_imports: &["GetDC", "CreateCompatibleDC", "CreateCompatibleBitmap", "BitBlt", "TextOutW"],
        benign_strings: &[],
    },
    Case {
        id: "clipboard-read",
        imports: &["OpenClipboard", "GetClipboardData", "CloseClipboard"],
        strings: &[],
        benign_imports: &["OpenClipboard", "EmptyClipboard", "SetClipboardData", "CloseClipboard"],
        benign_strings: &[],
    },
    Case {
        id: "raw-input-capture",
        imports: &["RegisterRawInputDevices", "GetRawInputData"],
        strings: &[],
        benign_imports: &["RegisterRawInputDevices", "GetRawInputDeviceInfoW"],
        benign_strings: &[],
    },
    Case {
        id: "service-control",
        imports: &["OpenSCManagerW", "OpenServiceW", "StartServiceW"],
        strings: &[],
        benign_imports: &["OpenSCManagerW", "OpenServiceW", "QueryServiceStatusEx", "EnumServicesStatusExW"],
        benign_strings: &[],
    },
    Case {
        id: "named-pipe-server",
        imports: &["CreateNamedPipeW", "ConnectNamedPipe"],
        strings: &[],
        benign_imports: &["CreatePipe", "ReadFile", "WriteFile"],
        benign_strings: &[],
    },
    Case {
        id: "named-pipe-client",
        imports: &["WaitNamedPipeW", "CreateFileW", "ReadFile"],
        strings: &["\\\\.\\pipe\\status-service"],
        benign_imports: &["CreateFileW", "ReadFile", "WriteFile"],
        benign_strings: &["C:\\reports\\pipe\\status.txt"],
    },
    Case {
        id: "dns-network",
        imports: &["getaddrinfo", "connect"],
        strings: &[],
        benign_imports: &["getaddrinfo", "gethostbyname", "freeaddrinfo"],
        benign_strings: &["https://example.org"],
    },
    Case {
        id: "system-info",
        imports: &["GetNativeSystemInfo", "GetComputerNameW", "GetEnvironmentVariableW"],
        strings: &[],
        benign_imports: &["GetEnvironmentVariableA", "GetEnvironmentVariableW", "GetEnvironmentStringsW"],
        benign_strings: &[],
    },
    Case {
        id: "lsa-private-data",
        imports: &["LsaOpenPolicy", "LsaRetrievePrivateData"],
        strings: &["DPAPI_SYSTEM"],
        benign_imports: &["LsaOpenPolicy", "LsaQueryInformationPolicy", "LsaLookupNames2"],
        benign_strings: &["LSA", "secrets", "SAM", "DPAPI_SYSTEM"],
    },
    Case {
        id: "credential-registry-read",
        imports: &["RegOpenKeyExW", "RegQueryValueExW"],
        strings: &["HKLM\\SAM\\Domains\\Account\\Users"],
        benign_imports: &["RegOpenKeyExW", "RegQueryValueExW"],
        benign_strings: &["SAM", "Secrets", "Software\\Vendor\\Credentials"],
    },
    Case {
        id: "ransomware-indicators",
        imports: &["BCryptEncrypt", "FindFirstFileW", "FindNextFileW", "WriteFile"],
        strings: &["YOUR FILES HAVE BEEN ENCRYPTED", "Pay the ransom to recover them"],
        benign_imports: &["BCryptEncrypt", "FindFirstFileW", "FindNextFileW", "WriteFile"],
        benign_strings: &["Encrypted backup complete", "Bitcoin wallet backup", "README.txt"],
    },
    Case {
        id: "remote-process-injection",
        imports: &["OpenProcess", "VirtualAllocEx", "CreateRemoteThread"],
        strings: &[],
        benign_imports: &["OpenProcess", "ReadProcessMemory", "VirtualQueryEx"],
        benign_strings: &[],
    },
    Case {
        id: "vm-sandbox-detection",
        imports: &["GetSystemFirmwareTable"],
        strings: &["VMware Virtual Platform"],
        benign_imports: &["GetSystemFirmwareTable"],
        benign_strings: &["SMBIOS firmware table version 3.2"],
    },
    Case {
        id: "system-shutdown",
        imports: &["InitiateSystemShutdownW"],
        strings: &["SeShutdownPrivilege"],
        benign_imports: &["InitiateSystemShutdownW"],
        benign_strings: &["The system is shutting down for maintenance"],
    },
];

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn capability(id: &str, imports: &[&str], strings: &[&str]) -> Option<Capability> {
    detect(&owned(imports), &owned(strings)).into_iter().find(|cap| cap.id == id)
}

#[test]
fn concrete_independent_indicators_match_with_original_evidence() {
    for case in CASES {
        let cap = capability(case.id, case.imports, case.strings).unwrap_or_else(|| panic!("missing {}", case.id));
        for import in case.imports {
            assert!(cap.evidence.contains(&format!("import:{import}")), "{}: {import}", case.id);
        }
        for string in case.strings {
            assert!(cap.evidence.contains(&format!("string:{string}")), "{}: {string}", case.id);
        }
        assert_eq!(cap.evidence.len(), case.imports.len() + case.strings.len(), "{}", case.id);
    }
}

#[test]
fn benign_related_metadata_does_not_imply_the_new_behavior() {
    for case in CASES {
        assert!(capability(case.id, case.benign_imports, case.benign_strings).is_none(), "{}", case.id);
    }
}

#[test]
fn lone_imports_or_strings_are_not_corroborated_behavior() {
    for case in CASES {
        for import in case.imports {
            assert!(capability(case.id, &[*import, *import], &[]).is_none(), "{}: {import}", case.id);
        }
        assert!(capability(case.id, &[], case.strings).is_none(), "{}: strings only", case.id);
    }
}

#[test]
fn each_independent_indicator_is_required_even_when_others_are_duplicated() {
    for case in CASES {
        for removed in 0..case.imports.len() {
            let remaining: Vec<&str> = case
                .imports
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != removed)
                .flat_map(|(_, import)| [*import, *import])
                .collect();
            assert!(capability(case.id, &remaining, case.strings).is_none(), "{}: import {removed}", case.id);
        }
        for removed in 0..case.strings.len() {
            let remaining: Vec<&str> = case
                .strings
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != removed)
                .flat_map(|(_, string)| [*string, *string])
                .collect();
            assert!(capability(case.id, case.imports, &remaining).is_none(), "{}: string {removed}", case.id);
        }
    }
}

#[test]
fn duplicated_inputs_do_not_duplicate_evidence_or_capabilities() {
    for case in CASES {
        let imports: Vec<&str> = case.imports.iter().flat_map(|import| [*import, *import]).collect();
        let strings: Vec<&str> = case.strings.iter().flat_map(|string| [*string, *string]).collect();
        let caps = detect(&owned(&imports), &owned(&strings));
        let matched: Vec<_> = caps.into_iter().filter(|cap| cap.id == case.id).collect();
        assert_eq!(matched.len(), 1, "{}", case.id);
        assert_eq!(matched[0], capability(case.id, case.imports, case.strings).unwrap());
    }
}

#[test]
fn import_aliases_cannot_replace_an_independent_indicator() {
    let cases: &[(&str, &[&str])] = &[
        ("persistence-registry-run", &["RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExW"]),
        ("persistence-service-install", &["OpenSCManagerA", "OpenSCManagerW"]),
        ("process-enumeration", &["CreateToolhelp32Snapshot", "Process32First", "Process32FirstA", "Process32FirstW"]),
        ("token-privilege", &["OpenProcessToken", "OpenThreadToken", "LookupPrivilegeValueA", "LookupPrivilegeValueW"]),
        ("screen-capture", &["GetDC", "GetWindowDC", "BitBlt", "StretchBlt"]),
        ("service-control", &["OpenSCManagerA", "OpenSCManagerW", "OpenServiceA", "OpenServiceW"]),
        ("named-pipe-server", &["CreateNamedPipeA", "CreateNamedPipeW"]),
        ("dns-network", &["getaddrinfo", "gethostbyname", "DnsQuery_A", "DnsQuery_W"]),
        ("system-info", &["GetSystemInfo", "GetNativeSystemInfo", "uname"]),
    ];
    for (id, imports) in cases {
        assert!(capability(id, imports, &[]).is_none(), "{id}");
    }
}

#[test]
fn registry_paths_are_case_insensitive_and_key_bounded() {
    let imports = &["RegOpenKeyExW", "RegSetValueExW"];
    for path in [
        "software\\microsoft\\windows\\currentversion\\RUN",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "hKlM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    ] {
        assert!(capability("persistence-registry-run", imports, &[path]).is_some());
    }
    for path in [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Runtime",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceBackup",
        "NotSoftware\\Microsoft\\Windows\\CurrentVersion\\Run",
    ] {
        assert!(capability("persistence-registry-run", imports, &[path]).is_none(), "{path}");
    }
    assert!(
        capability(
            "credential-registry-read",
            &["RegOpenKeyExW", "RegQueryValueExW"],
            &["HKLM\\security\\POLICY\\Secrets\\DefaultPassword"]
        )
        .is_some()
    );
    assert!(
        capability(
            "credential-registry-read",
            &["RegOpenKeyExW", "RegQueryValueExW"],
            &["SAM\\Domains\\Account\\UsersBackup"]
        )
        .is_none()
    );
}

#[test]
fn autorun_paths_require_exact_keys_not_child_keys() {
    let imports = &["RegOpenKeyExW", "RegSetValueExW"];
    for hive in ["", "HKCU\\", "HKEY_LOCAL_MACHINE\\"] {
        for key in ["Run", "RunOnce"] {
            let path = format!("{hive}Software\\Microsoft\\Windows\\CurrentVersion\\{key}\\VendorBackup");
            assert!(capability("persistence-registry-run", imports, &[&path]).is_none(), "{path}");
        }
    }
}

#[test]
fn registry_paths_reject_nested_ancestors_and_inappropriate_hives() {
    let autorun_imports = &["RegOpenKeyExW", "RegSetValueExW"];
    for path in [
        "HKCU\\Software\\Vendor\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\Vendor\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Vendor\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCR\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_CLASSES_ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLMBackup\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    ] {
        assert!(capability("persistence-registry-run", autorun_imports, &[path]).is_none(), "{path}");
    }
    let read_imports = &["RegOpenKeyExW", "RegQueryValueExW"];
    for path in [
        "HKCU\\SAM\\Domains\\Account\\Users",
        "HKEY_CURRENT_USER\\security\\policy\\secrets",
        "hkcU\\sAm\\Domains\\Account\\Users",
        "HKCR\\SAM\\Domains\\Account\\Users",
        "HKEY_USERS\\S-1-5-21-123\\SECURITY\\Policy\\Secrets",
        "\\Registry\\User\\S-1-5-21-123\\SAM\\Domains\\Account\\Users",
        "HKLM\\Software\\Vendor\\SAM\\Domains\\Account\\Users",
        "HKLM\\Software\\Vendor\\SECURITY\\Policy\\Secrets",
        "Software\\Vendor\\SAM\\Domains\\Account\\Users",
        "HKLMBackup\\SAM\\Domains\\Account\\Users",
    ] {
        assert!(capability("credential-registry-read", read_imports, &[path]).is_none(), "{path}");
    }
}

#[test]
fn protected_registry_paths_accept_bare_and_recognized_machine_roots() {
    let imports = &["RegOpenKeyExW", "RegQueryValueExW"];
    for path in [
        "SAM\\Domains\\Account\\Users",
        "security\\policy\\secrets\\DefaultPassword",
        "HKLM\\SAM\\Domains\\Account\\Users",
        "HKLM\\SAM\\Domains\\Account\\Users\\000001F4",
        "hKeY_lOcAl_MaChInE\\SECURITY\\Policy\\Secrets",
        "\\Registry\\Machine\\SAM\\Domains\\Account\\Users",
    ] {
        let cap = capability("credential-registry-read", imports, &[path]).unwrap_or_else(|| panic!("{path}"));
        assert!(cap.evidence.contains(&format!("string:{path}")));
    }
}

#[test]
fn normalized_imports_preserve_raw_names_in_evidence() {
    let imports = &["_CreateToolhelp32Snapshot@4", "PROCESS32FIRSTW", "Process32NextW@plt"];
    let cap = capability("process-enumeration", imports, &[]).unwrap();
    assert_eq!(cap.evidence, imports.iter().map(|name| format!("import:{name}")).collect::<Vec<_>>());
}

#[test]
fn posix_system_and_file_encryption_indicators_use_the_same_roles() {
    assert!(capability("system-info", &["uname", "gethostname", "getenv"], &[]).is_some());
    assert!(
        capability(
            "ransomware-indicators",
            &["EVP_EncryptUpdate", "opendir", "readdir", "fwrite"],
            &["All your files are encrypted. Bitcoin payment to decrypt is required."]
        )
        .is_some()
    );
}

#[test]
fn overlapping_note_phrases_produce_one_raw_evidence_entry() {
    let note = "Your files have been encrypted. Pay the ransom.";
    let cap = capability(
        "ransomware-indicators",
        &["CryptEncrypt", "FindFirstFileA", "FindNextFileA", "WriteFile"],
        &[note, note],
    )
    .unwrap();
    assert_eq!(cap.evidence.iter().filter(|value| value.starts_with("string:")).count(), 1);
    assert!(cap.evidence.contains(&format!("string:{note}")));
}

#[test]
fn legacy_thresholds_count_terms_not_raw_evidence_entries() {
    assert!(capability("process-injection", &["WriteProcessMemory", "_WriteProcessMemory@20"], &[]).is_none());
    let cap = capability("process-injection", &["VirtualAllocEx", "_WriteProcessMemory@20"], &[]).unwrap();
    assert_eq!(cap.evidence, vec!["import:virtualallocex", "import:writeprocessmemory"]);
}

#[test]
fn legacy_evidence_preserves_canonical_tokens_and_one_entry_per_term() {
    let cap = capability("anti-debug", &["_ptrace", "PTRACE", "ptrace@plt", "_ptrace"], &[]).unwrap();
    assert_eq!(cap.evidence, vec!["import:ptrace"]);
    let cap = capability(
        "http-client",
        &[],
        &[
            "visit https://example.org/path",
            "https://example.net/other",
            "visit https://example.org/path",
            "User-Agent: application",
        ],
    )
    .unwrap();
    assert_eq!(cap.evidence, vec!["string:User-Agent:", "string:https://"]);
    let cap = capability("network-socket", &["CONNECT", "_connect@plt", "send", "SEND"], &[]).unwrap();
    assert_eq!(cap.evidence, vec!["import:connect", "import:send"]);
}
