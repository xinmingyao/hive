local cell = require "cell"
local ice_peer = require "p2p.ice_peer"
local peer
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

function cell.main(port)
   
   if not port  then
      port = 9000
   end
   print("client start:",port)
   local streams_info =
      {sid=1,
       components = {
	  {
	     cid=1,user="client",pwd="pwd1",port=port
	  }
       }
      }
   local stun_servers =
      {
	 {ip="107.23.150.92",port=3478}
      }
   local opts = {}
   peer =  ice_peer:new(streams_info,stun_servers,opts)
   local info = peer:offer()
   return info
end

cell.message {
   receive = function(...)
      print(...)
   end,
   ping = function(Remotes)
      peer:set_remotes(Remotes)
   end,
   ice_completed = function()
      
   end
}
