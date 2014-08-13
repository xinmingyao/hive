local cell = require "cell"
local crypto = require "crypto"
local digest = crypto.digest
local hmac = crypto.hmac
local base64 = require "base64"
local c = require "cell.c"
cell.command {
   ping = function()
      return "pong"
   end,
   sleep = function(T)
      cell.sleep(T)
      return true
   end
}


function cell.main()
   local meeting_manager = cell.cmd("launch","mcu.meeting_manager")
   local db_imp = cell.cmd("launch","mcu.db_imp")
   local auth = cell.cmd("launch","mcu.auth")
   print(cell.listen("192.168.203.157:8085",function(fd,msg)
			local s = cell.cmd("launch", "mcu.ws_gate",fd,db_imp,meeting_manager,auth)		  
			return s
   end))
end   

