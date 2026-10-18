#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

int main(void) {
    lua_State *state = luaL_newstate();
    if (!state) return 1;
    luaL_openlibs(state);
    lua_pushinteger(state, 42);
    int result = (int)lua_tointeger(state, -1);
    lua_close(state);
    return result;
}
