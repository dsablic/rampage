#include "sqlite3.h"

int main(void) {
    sqlite3 *database = 0;
    sqlite3_stmt *statement = 0;
    int result = sqlite3_open(":memory:", &database);
    if (result != SQLITE_OK) {
        sqlite3_close(database);
        return 1;
    }
    result = sqlite3_prepare_v2(database, "SELECT length(?1), upper(?1)", -1, &statement, 0);
    if (result == SQLITE_OK)
        result = sqlite3_bind_text(statement, 1, "reference-token", -1, SQLITE_STATIC);
    if (result == SQLITE_OK)
        result = sqlite3_step(statement);
    int failed = result != SQLITE_ROW;
    if (!failed)
        failed = sqlite3_column_int(statement, 0) != 15;
    sqlite3_finalize(statement);
    sqlite3_close(database);
    return failed;
}
