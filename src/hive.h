#ifndef hive_h
#define hive_h
#define GUI_PORT 7
#define WM_HIVE_CELL 103



LUALIB_API int luaopen_cmsgpack (lua_State *L);
LUALIB_API int luaopen_binlib_c (lua_State *L);



#if defined(_WIN32)
#include <windows.h>
#define HIVE_API __declspec(dllexport)

HIVE_API
lua_State * gui_new();

#endif

#endif
