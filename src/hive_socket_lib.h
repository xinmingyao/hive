#ifndef hive_socket_lib_h
#define hive_socket_lib_h

#include "lua.h"
#define LHIVE_STATE_NEW       1
#define LHIVE_STATE_CONNECTED 2
#define LHIVE_STATE_CLOSED    3
#define SSL_TLS  1
#define SSL_DTLS  2
int socket_lib(lua_State *L);

#endif
