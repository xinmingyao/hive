#include "hive_cell_lib.h"
#include "hive_env.h"
#include "hive_seri.h"
#include "hive_cell.h"
#include "hive_seri.h"
#include "stable.h"
#include "hive.h"

#include "lua.h"
#include "lauxlib.h"

#include <string.h>
static int
ldispatch(lua_State *L) {
	luaL_checktype(L, 1, LUA_TFUNCTION);
	lua_settop(L,1);
	hive_setenv(L, "dispatcher");
	return 0;
}
static int
get_cell(lua_State *L) {
	const char * name;
	name  = luaL_checkstring(L,1);
	hive_getenv(L,"cell_registar");
	struct table * registar = lua_touserdata(L,-1);
	lua_pop(L,1);
	struct cell * c =(struct cell *)stable_id(registar,name,strlen(name));
	if(c == NULL){
		return NULL;
	}else{
		return c;
	}
		
}

static int
iup_send(lua_State *L) {
	struct cell * c = get_cell(L);
	if (c==NULL) {
		return luaL_error(L, "Need cell object at param 1");
	}
	int port = luaL_checkinteger(L,2);
	if (lua_gettop(L) == 2) {
		if (cell_send(c, port, NULL,0)) {
			return luaL_error(L, "Cell object %p is closed",c);
		}
		return 0;
	}
	lua_pushcfunction(L, data_pack);
	lua_replace(L,2);	// cell data_pack ...
	int n = lua_gettop(L);
	lua_call(L, n-2, 1);
	void * msg = lua_touserdata(L,2);
	if (cell_send(c, port, msg,0)) {
		lua_pushcfunction(L, data_unpack);
		lua_pushvalue(L,2);
		hive_getenv(L, "cell_map");
		lua_call(L,2,0);
		return luaL_error(L, "Cell object %p is closed", c);
	}

	return 0;
}


static int
lsend(lua_State *L) {
	struct cell * c = cell_fromuserdata(L, 1);
	if (c==NULL) {
		return luaL_error(L, "Need cell object at param 1");
	}
	int port = luaL_checkinteger(L,2);
	if (lua_gettop(L) == 2) {
		if (cell_send(c, port, NULL,0)) {
			return luaL_error(L, "Cell object %p is closed",c);
		}
		return 0;
	}
	lua_pushcfunction(L, data_pack);
	lua_replace(L,2);	// cell data_pack ...
	int n = lua_gettop(L);
	lua_call(L, n-2, 1);
	void * msg = lua_touserdata(L,2);
	if (cell_send(c, port, msg,0)) {
		lua_pushcfunction(L, data_unpack);
		lua_pushvalue(L,2);
		hive_getenv(L, "cell_map");
		lua_call(L,2,0);
		return luaL_error(L, "Cell object %p is closed", c);
	}

	return 0;
}
static int
lregister(lua_State *L) {
  const char * name = luaL_checkstring(L,1);
  if(strlen(name) >= 50){
    return luaL_error(L,"name:%s is too long,max is 49",name);
  }
  hive_getenv(L,"cell_registar");
  struct table * tmp = lua_touserdata(L,-1);

  if(tmp == NULL) {
    return luaL_error(L,"no cell_registar ");
  }
  hive_getenv(L, "cell_pointer");
  struct cell * c = lua_touserdata(L,-1);
  if(c == NULL) {
    return luaL_error(L,"no cell_pointer ");
  }
  cell_setname(c,name);
  stable_setid(tmp,name,strlen(name),(uint64_t)(uintptr_t)c);
  lua_pop(L,2);
  return 0;
}




#if defined(_WIN32)
#include <windows.h>
//post msg to win handle
static int
lpost_message(lua_State *L) {
  HWND handle;
  int port;
  char * msg;
  char * cmd;
  int t = lua_type(L,1);
  if(t == LUA_TSTRING) {
    const char * handle_name=luaL_checkstring(L,1);
    hive_getenv(L,"win_handle_registar");
    struct table * registar = lua_touserdata(L,-1);
    lua_pop(L,1);
    handle = (HWND)stable_id(registar,handle_name,strlen(handle_name));
  } else {
    handle = (HWND)luaL_checkinteger(L,1);
  }
  port = luaL_checkinteger(L,2);
  data_pack(L);
  msg = lua_touserdata(L,-1);
  PostMessage(handle,WM_HIVE_CELL,port,msg); //msg must send to gui,free in gui
  return 0;
}

HIVE_API
int
regist_handle(lua_State *L,char * name,int size,HWND handle) {
  hive_getenv(L,"win_handle_registar");
  struct table * registar = lua_touserdata(L,-1);
  lua_pop(L,1);
  stable_setid(registar,name,size,(uint64_t)handle);
  return 0;
}


HIVE_API
int
send_to_cell(lua_State *L,char * name,char * msg,int size){
  hive_getenv(L,"cell_registar");
  struct table * registar = lua_touserdata(L,-1);
  lua_pop(L,1);
  struct cell * c =(struct cell *)stable_id(registar,name,strlen(name));
  if(c == NULL){
	return 2;
  }
  if(cell_send(c,GUI_PORT,msg,size)) {
    return 1; //cell closed
  }
  return 0;
}



static int
send_dispatch(lua_State *L) {
	if(lua_type(L,1) == LUA_TSTRING||lua_type(L,1) == LUA_TNUMBER){//to gui winhandle
		return lpost_message(L);
	}else{
		return lsend(L); //to cell
	}
}


#endif

static int
lregister_monitor(lua_State *L) {
  struct cell * c = cell_fromuserdata(L,1);
  int r = register_monitor(c);
  lua_pushboolean(L,r);
  return 1;

}


static int
ldata_unpack(lua_State *L) {
	hive_getenv(L, "cell_map");
	lua_insert(L, 2);
	return data_unpack(L);
}

static int
lmonitor_cell(lua_State *L) {
  struct cell * c = monitor_cell();
  if (c) {
    hive_getenv(L,"cell_map");
    int cell_map = lua_absindex(L,-1);
    cell_touserdata(L,cell_map,c);
    return 1;
  }else{
    return 0;
  }
}
int
cell_lib(lua_State *L) {
	luaL_checkversion(L);
	luaL_Reg l[] = {
		{ "dispatch", ldispatch },
		{ "iup_send", iup_send },
		{ "register", lregister },
		{ "data_unpack", ldata_unpack},
		{ "register_monitor", lregister_monitor},
		{ "monitor_cell",lmonitor_cell},
#if defined(_WIN32)
		{"post_message",lpost_message},
		{ "send", send_dispatch },
#else
		{ "send", lsend },
#endif
		{ NULL, NULL },
	};
	luaL_newlib(L,l);
	return 1;
}

