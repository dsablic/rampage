#include "lua.h"
#include "lauxlib.h"

static __attribute__((noinline)) unsigned target_seed(unsigned value) {
    for (unsigned index = 0; index < 23; ++index)
        value = value * 19u + (value >> 7) + index;
    return value;
}

int main(int argc, char **argv) {
    lua_State *state = luaL_newstate();
    if (!state) return 1;
    lua_pushstring(state, argv[0]);
    lua_pushinteger(state, target_seed((unsigned)argc));
    int result = lua_gettop(state);
    lua_close(state);
    return result;
}
