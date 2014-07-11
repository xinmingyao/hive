local cell = require "cell"

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
local client = require "protocol.ws_client"
local ws_proto = require "protocol.ws_proto"
function test_client()
   ws = client.new()
   ws:connect("ws://192.168.203.157:8085/t")
   ws:send_text("ping1")
   print("111:",ws:recv_frame())
   ws:send_text("ping2")
   print("222:",ws:recv_frame())
   ws:send_text("ping3")
end

function start_server()
   print(cell.listen("192.168.203.157:8085",function(fd,msg)
		  local s = cell.cmd("launch", "socket_io.io",fd)
		  return s
   end))
end
function cell.main()
   --ws_proto.parse_test()
  
   start_server()
   --test_client()
   return 
end
