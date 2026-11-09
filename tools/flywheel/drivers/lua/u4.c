/* Flywheel corpus driver: Lua tables from C, iteration and the collector. Never run; it only has to link. */
#include <stdio.h>
#include "lua.h"
#include "lauxlib.h"

int main(int argc, char **argv) {
    lua_State *state = luaL_newstate();
    lua_newtable(state);
    for (int i = 1; i < argc || i <= 3; i++) {
        lua_pushstring(state, i < argc ? argv[i] : "value");
        lua_rawseti(state, -2, i);
    }
    lua_pushinteger(state, 42);
    lua_setfield(state, -2, "answer");
    int count = 0;
    lua_pushnil(state);
    while (lua_next(state, -2) != 0) {
        if (lua_type(state, -1) == LUA_TSTRING) count++;
        lua_pop(state, 1);
    }
    lua_getfield(state, -1, "answer");
    lua_Integer answer = lua_tointeger(state, -1);
    lua_gc(state, LUA_GCCOLLECT, 0);
    printf("%d %lld %d\n", count, (long long)answer, lua_gc(state, LUA_GCCOUNT, 0));
    lua_close(state);
    return 0;
}
