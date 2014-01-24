local cell = require "cell"
local stun_socket
local stun 
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

cell.message {
   accept_udp = function(...)
      print("udp:")
      cell.send(stun,"udp",...)
   end,
   stun_rep = function(...)
      print("send to stun")
      stun_socket:write(...)
   end
}
function cell.main()
   local ip = "192.168.203.157"
   local port = 3478
   local stun_server = "107.23.150.92"
   local stun_port = port
   --local stun_server = "192.168.203.157"

   stun = cell.cmd("launch","p2p.stun")
   stun_socket = cell.open(port,cell.self,{protocol = "p2p"})
   print(cell.self)
   print(stun)
   local ok,s = cell.call(stun,"start",cell.self,ip,port,stun_server,stun_port)
   print(ok,s.nat_type)
   return true
end
