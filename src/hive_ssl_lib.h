#ifndef LSEC_SSL_H
#define LSEC_SSL_H

/*--------------------------------------------------------------------------
 * LuaSec 0.5
 * Copyright (C) 2006-2014 Bruno Silvestre
 *
 *--------------------------------------------------------------------------*/



#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>

#include <lua.h>
#include <lauxlib.h>

typedef struct hive_ssl_ {
  int  id;
  SSL *ssl;
  int state;
  int error;
} hive_ssl;



#define LHIVE_IO_SSL          -100

HIVE_API int luaopen_ssl_core(lua_State *L);

#endif
