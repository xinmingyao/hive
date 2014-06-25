local cell = require "cell"
local ws_server = require "protocol.ws_server"
local socket
local server  
cell.command {
	ping = function()
		cell.sleep(1)
		return "pong"
	end,
	sleep = function(T)
	      cell.sleep(T)
	      return true
	end
}

local  handle = {
   text = function(msg)
      print("receive:",msg)
      server:send_text(msg)
   end  
}
function cell.main(fd)
   cell.timeout(0,function()
		   server,err = ws_server.new(fd,handle)
		   if server then
		      return true
		   else
		      print("error",err)
		      return false
		   end
   end)
end
