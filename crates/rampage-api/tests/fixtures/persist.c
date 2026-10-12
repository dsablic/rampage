/* Persistence-shaped code for workflow tests: it names autostart locations and writes to them. The tests only
 * analyze the compiled program, they never run it. Built for Linux (paths and file writes) and for Windows
 * (registry Run key, service creation and a scheduled-task command line). */
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

static const char *run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static const char *task = "schtasks /create /tn Updater /sc onlogon /tr updater.exe";

__attribute__((noinline)) static int add_run_value(const char *command) {
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, run_key, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS)
        return -1;
    LONG status = RegSetValueExA(key, "Updater", 0, REG_SZ, (const BYTE *)command, (DWORD)strlen(command) + 1);
    RegCloseKey(key);
    return status == ERROR_SUCCESS ? 0 : -1;
}

__attribute__((noinline)) static int install_service(const char *binary) {
    SC_HANDLE manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!manager)
        return -1;
    SC_HANDLE service = CreateServiceA(manager, "Updater", "Updater", SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                       SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binary, NULL, NULL, NULL, NULL, NULL);
    if (service)
        CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return service ? 0 : -1;
}

int main(int argc, char **argv) {
    const char *self = argc > 0 ? argv[0] : "updater.exe";
    if (add_run_value(self) != 0 && install_service(self) != 0)
        puts(task);
    return 0;
}
#else
static const char *unit = "/etc/systemd/system/updater.service";
static const char *cron = "/etc/cron.d/updater";
static const char *autostart = ".config/autostart/updater.desktop";
static const char *agent = "Library/LaunchAgents/com.example.updater.plist";
static const char *rc = ".bashrc";

__attribute__((noinline)) static int append_line(const char *path, const char *line) {
    FILE *file = fopen(path, "a");
    if (!file)
        return -1;
    fputs(line, file);
    return fclose(file);
}

__attribute__((noinline)) static int install_unit(const char *binary) {
    char line[256];
    snprintf(line, sizeof line, "[Service]\nExecStart=%s\n[Install]\nWantedBy=multi-user.target\n", binary);
    return append_line(unit, line);
}

int main(int argc, char **argv) {
    const char *self = argc > 0 ? argv[0] : "updater";
    if (install_unit(self) != 0)
        append_line(cron, "@reboot root /usr/local/bin/updater\n");
    append_line(argc > 1 ? autostart : agent, self);
    append_line(rc, self);
    return 0;
}
#endif
