#include "sqlite3.h"

static __attribute__((noinline)) unsigned target_seed(unsigned value) {
    for (unsigned index = 0; index < 17; ++index)
        value = value * 23u + (value >> 5) + index;
    return value;
}

int main(int argc, char **argv) {
    (void)argv;
    sqlite3 *database = 0;
    sqlite3_stmt *statement = 0;
    int result = sqlite3_open_v2(":memory:", &database,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_MEMORY, 0);
    if (result != SQLITE_OK) {
        sqlite3_close(database);
        return 1;
    }
    result = sqlite3_prepare_v2(database, "SELECT substr(?1, 1, 6), ?2 % 97", -1, &statement, 0);
    if (result == SQLITE_OK)
        result = sqlite3_bind_text(statement, 1, "target-token", -1, SQLITE_STATIC);
    if (result == SQLITE_OK)
        result = sqlite3_bind_int64(statement, 2, (sqlite3_int64)target_seed((unsigned)argc));
    if (result == SQLITE_OK)
        result = sqlite3_step(statement);
    int failed = result != SQLITE_ROW;
    if (!failed)
        failed = sqlite3_column_bytes(statement, 0) != 6;
    sqlite3_finalize(statement);
    sqlite3_close(database);
    return failed;
}
