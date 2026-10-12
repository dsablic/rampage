use super::{CorroboratedRule, Match, RegistryHive};

pub(super) const RULES: &[CorroboratedRule] = &[
    CorroboratedRule {
        id: "persistence-registry-run",
        name: "Registry autorun modification indicators",
        category: "persistence",
        groups: &[
            &[
                Match::Import("regopenkeyexa"),
                Match::Import("regopenkeyexw"),
                Match::Import("regcreatekeyexa"),
                Match::Import("regcreatekeyexw"),
            ],
            &[Match::Import("regsetvalueexa"), Match::Import("regsetvalueexw")],
            &[
                Match::RegistryPath {
                    path: "software\\microsoft\\windows\\currentversion\\run",
                    hive: RegistryHive::UserOrMachine,
                    exact_key: true,
                },
                Match::RegistryPath {
                    path: "software\\microsoft\\windows\\currentversion\\runonce",
                    hive: RegistryHive::UserOrMachine,
                    exact_key: true,
                },
            ],
        ],
    },
    CorroboratedRule {
        id: "persistence-scheduled-task",
        name: "Scheduled task registration indicators",
        category: "persistence",
        groups: &[
            &[Match::Import("cocreateinstance"), Match::Import("cocreateinstanceex")],
            &[Match::String("Schedule.Service"), Match::String("ITaskService"), Match::String("CLSID_TaskScheduler")],
            &[Match::String("RegisterTaskDefinition"), Match::String("ITaskFolder::RegisterTask")],
        ],
    },
    CorroboratedRule {
        id: "persistence-service-install",
        name: "Service installation indicators",
        category: "persistence",
        groups: &[
            &[Match::Import("openscmanagera"), Match::Import("openscmanagerw")],
            &[Match::Import("createservicea"), Match::Import("createservicew")],
        ],
    },
    CorroboratedRule {
        id: "process-enumeration",
        name: "Process snapshot enumeration indicators",
        category: "discovery",
        groups: &[
            &[Match::Import("createtoolhelp32snapshot")],
            &[Match::Import("process32first"), Match::Import("process32firsta"), Match::Import("process32firstw")],
            &[Match::Import("process32next"), Match::Import("process32nexta"), Match::Import("process32nextw")],
        ],
    },
    CorroboratedRule {
        id: "token-privilege",
        name: "Token privilege adjustment indicators",
        category: "host",
        groups: &[
            &[Match::Import("openprocesstoken"), Match::Import("openthreadtoken")],
            &[Match::Import("lookupprivilegevaluea"), Match::Import("lookupprivilegevaluew")],
            &[Match::Import("adjusttokenprivileges")],
        ],
    },
    CorroboratedRule {
        id: "debug-privilege",
        name: "Debug privilege adjustment indicators",
        category: "host",
        groups: &[
            &[Match::Import("openprocesstoken"), Match::Import("openthreadtoken")],
            &[Match::Import("lookupprivilegevaluea"), Match::Import("lookupprivilegevaluew")],
            &[Match::Import("adjusttokenprivileges")],
            &[Match::String("SeDebugPrivilege")],
        ],
    },
    CorroboratedRule {
        id: "screen-capture",
        name: "GDI screen capture indicators",
        category: "collection",
        groups: &[
            &[Match::Import("getdc"), Match::Import("getwindowdc")],
            &[Match::Import("createcompatibledc")],
            &[Match::Import("createcompatiblebitmap"), Match::Import("createdibsection")],
            &[Match::Import("bitblt"), Match::Import("stretchblt")],
            &[Match::Import("getdibits")],
        ],
    },
    CorroboratedRule {
        id: "clipboard-read",
        name: "Clipboard data access indicators",
        category: "collection",
        groups: &[
            &[Match::Import("openclipboard")],
            &[Match::Import("getclipboarddata")],
            &[Match::Import("closeclipboard")],
        ],
    },
    CorroboratedRule {
        id: "raw-input-capture",
        name: "Registered raw input capture indicators",
        category: "collection",
        groups: &[&[Match::Import("registerrawinputdevices")], &[Match::Import("getrawinputdata")]],
    },
    CorroboratedRule {
        id: "service-control",
        name: "Service control indicators",
        category: "host",
        groups: &[
            &[Match::Import("openscmanagera"), Match::Import("openscmanagerw")],
            &[Match::Import("openservicea"), Match::Import("openservicew")],
            &[
                Match::Import("startservicea"),
                Match::Import("startservicew"),
                Match::Import("controlservice"),
                Match::Import("controlserviceexa"),
                Match::Import("controlserviceexw"),
                Match::Import("changeserviceconfiga"),
                Match::Import("changeserviceconfigw"),
                Match::Import("deleteservice"),
            ],
        ],
    },
    CorroboratedRule {
        id: "named-pipe-server",
        name: "Named pipe server IPC indicators",
        category: "host",
        groups: &[
            &[Match::Import("createnamedpipea"), Match::Import("createnamedpipew")],
            &[Match::Import("connectnamedpipe")],
        ],
    },
    CorroboratedRule {
        id: "named-pipe-client",
        name: "Named pipe client IPC indicators",
        category: "host",
        groups: &[
            &[Match::Import("waitnamedpipea"), Match::Import("waitnamedpipew")],
            &[Match::Import("createfilea"), Match::Import("createfilew")],
            &[Match::Import("readfile"), Match::Import("writefile")],
            &[Match::StringAsciiInsensitive("\\\\.\\pipe\\")],
        ],
    },
    CorroboratedRule {
        id: "dns-network",
        name: "DNS resolution with network communication indicators",
        category: "networking",
        groups: &[
            &[
                Match::Import("getaddrinfo"),
                Match::Import("gethostbyname"),
                Match::Import("getaddrinfow"),
                Match::Import("getaddrinfoexa"),
                Match::Import("getaddrinfoexw"),
                Match::Import("dnsquery_a"),
                Match::Import("dnsquery_w"),
                Match::Import("dnsquery_utf8"),
                Match::Import("dnsqueryex"),
            ],
            &[
                Match::Import("connect"),
                Match::Import("wsaconnect"),
                Match::Import("sendto"),
                Match::Import("wsasendto"),
            ],
        ],
    },
    CorroboratedRule {
        id: "system-info",
        name: "System and environment information gathering indicators",
        category: "discovery",
        groups: &[
            &[Match::Import("getsysteminfo"), Match::Import("getnativesysteminfo"), Match::Import("uname")],
            &[
                Match::Import("getcomputernamea"),
                Match::Import("getcomputernamew"),
                Match::Import("getcomputernameexa"),
                Match::Import("getcomputernameexw"),
                Match::Import("gethostname"),
            ],
            &[
                Match::Import("getenvironmentvariablea"),
                Match::Import("getenvironmentvariablew"),
                Match::Import("getenvironmentstrings"),
                Match::Import("getenvironmentstringsa"),
                Match::Import("getenvironmentstringsw"),
                Match::Import("getenv"),
            ],
        ],
    },
    CorroboratedRule {
        id: "lsa-private-data",
        name: "LSA credential private-data access indicators",
        category: "collection",
        groups: &[
            &[Match::Import("lsaopenpolicy")],
            &[Match::Import("lsaretrieveprivatedata")],
            &[Match::String("DefaultPassword"), Match::String("DPAPI_SYSTEM"), Match::String("NL$KM")],
        ],
    },
    CorroboratedRule {
        id: "credential-registry-read",
        name: "Protected credential registry read indicators",
        category: "collection",
        groups: &[
            &[Match::Import("regopenkeyexa"), Match::Import("regopenkeyexw")],
            &[Match::Import("regqueryvalueexa"), Match::Import("regqueryvalueexw")],
            &[
                Match::RegistryPath {
                    path: "sam\\domains\\account\\users",
                    hive: RegistryHive::Machine,
                    exact_key: false,
                },
                Match::RegistryPath {
                    path: "security\\policy\\secrets",
                    hive: RegistryHive::Machine,
                    exact_key: false,
                },
            ],
        ],
    },
    CorroboratedRule {
        id: "ransomware-indicators",
        name: "File encryption and ransom-note indicators",
        category: "impact",
        groups: &[
            &[
                Match::Import("cryptencrypt"),
                Match::Import("bcryptencrypt"),
                Match::Import("evp_encryptupdate"),
                Match::Import("aes_encrypt"),
            ],
            &[Match::Import("findfirstfilea"), Match::Import("findfirstfilew"), Match::Import("opendir")],
            &[Match::Import("findnextfilea"), Match::Import("findnextfilew"), Match::Import("readdir")],
            &[Match::Import("writefile"), Match::Import("fwrite")],
            &[
                Match::StringAsciiInsensitive("your files have been encrypted"),
                Match::StringAsciiInsensitive("all your files are encrypted"),
            ],
            &[
                Match::StringAsciiInsensitive("pay the ransom"),
                Match::StringAsciiInsensitive("bitcoin payment to decrypt"),
            ],
        ],
    },
];

#[cfg(test)]
mod tests;
