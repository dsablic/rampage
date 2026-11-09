/* Flywheel corpus driver: Lua with a custom allocator, two libraries and a C function. Never run. */
#include <stdio.h>
#include <stdlib.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static void *drv_alloc(void *ud, void *block, size_t old_size, size_t new_size) {
    (void)ud;
    (void)old_size;
    if (new_size == 0) {
        free(block);
        return NULL;
    }
    return realloc(block, new_size);
}

static int drv_add(lua_State *state) {
    lua_Integer left = luaL_checkinteger(state, 1);
    lua_Integer right = luaL_optinteger(state, 2, 1);
    lua_pushinteger(state, left + right);
    return 1;
}

int main(int argc, char **argv) {
    lua_State *state = lua_newstate(drv_alloc, NULL);
    luaL_requiref(state, "_G", luaopen_base, 1);
    luaL_requiref(state, "string", luaopen_string, 1);
    lua_settop(state, 0);
    lua_pushcfunction(state, drv_add);
    lua_setglobal(state, "add");
    const char *chunk = argc > 1 ? argv[1] : "return string.format('%d', add(40, 2))";
    int status = luaL_loadstring(state, chunk) || lua_pcall(state, 0, 1, 0);
    printf("%d %s\n", status, lua_tostring(state, -1));
    lua_close(state);
    return 0;
}
