/* Flywheel corpus driver: Lua with every standard library, running a chunk. Never run; it only has to link. */
#include <stdio.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

int main(int argc, char **argv) {
    lua_State *state = luaL_newstate();
    luaL_openlibs(state);
    const char *chunk = argc > 1 ? argv[1] : "local t = {} for i = 1, 10 do t[#t + 1] = i * i end return #t";
    if (luaL_dostring(state, chunk) != LUA_OK) {
        printf("error: %s\n", lua_tostring(state, -1));
        lua_close(state);
        return 1;
    }
    printf("%g\n", (double)lua_tonumber(state, -1));
    lua_close(state);
    return 0;
}
