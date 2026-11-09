/* Flywheel corpus driver: Lua bytecode dump and reload. Never run; it only has to link. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lua.h"
#include "lauxlib.h"

struct drv_buffer {
    char *data;
    size_t size;
};

static int drv_writer(lua_State *state, const void *chunk, size_t size, void *ud) {
    (void)state;
    struct drv_buffer *buffer = ud;
    char *grown = realloc(buffer->data, buffer->size + size);
    if (!grown) return 1;
    memcpy(grown + buffer->size, chunk, size);
    buffer->data = grown;
    buffer->size += size;
    return 0;
}

int main(int argc, char **argv) {
    lua_State *state = luaL_newstate();
    const char *source = argc > 1 ? argv[1] : "local a, b = 6, 7 return a * b";
    struct drv_buffer buffer = {NULL, 0};
    if (luaL_loadbuffer(state, source, strlen(source), "driver") == LUA_OK) lua_dump(state, drv_writer, &buffer, 1);
    lua_settop(state, 0);
    int status = luaL_loadbuffer(state, buffer.data, buffer.size, "bytecode");
    if (status == LUA_OK) status = lua_pcall(state, 0, 1, 0);
    printf("%zu %d %g\n", buffer.size, status, (double)lua_tonumber(state, -1));
    free(buffer.data);
    lua_close(state);
    return 0;
}
