#include "hive_ssl_lib.h"



static int
ldtls_new(lua_State *L) {
  int fd = luaL_checkinteger(L,1);
  return 0;
}

static int
lssl_handshake(lua_State *L) {
   int err;
   hive_ssl * ssl;
   ERR_clear_error();
   err = SSL_do_handshake(ssl->ssl);
   lua_pushinteger(L,err);
   return 1;
}

int
cell_lib(lua_State *L) {
  luaL_checkversion(L);
  luaL_Reg l[] = {
    { "dtls_new", ldtls_new },
    { "ssl_handshake", lssl_handshake},
    { NULL, NULL },
	};
	luaL_newlib(L,l);
	return 1;
}

