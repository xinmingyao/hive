local cell = require "cell"
local ice_peer = require "p2p.ice_peer"
local peer
local sid = 1
local cid = 1
cell.command {
	ping = function()
		cell.sleep(1)
		return "pong"
	end,
	sleep = function(T)
	      cell.sleep(T)
	      return true
	end,
	set_remotes = function(...)
	   return peer:set_remotes(Remotes)
	end,
	ping = function(Remotes)
	   peer:send(sid,cid,"ping")
	   --assert(pong == "pong")
	end
	
}

cell.message {
   receive = function(...)
      print(...)
   end
}

function cell.main(port,remotes)
   
   if not port  then
      port = 9000
   end
   print("server start:",port)
   local streams_info =
      {
	 {sid=1,
	  components = {
	     {
		cid=1,user="server",pwd="server",port=port,ip="192.168.203.157"
	     }
	  }
	 }
      }
   local stun_servers =
      {
	 {ip="107.23.150.92",port=3478}
      }
   local opts = {}
   peer = ice_peer.new(streams_info,stun_servers,opts)
   local ok,info = peer:answer()
   cell.timeout(0,function()
		   peer:set_remotes(remotes)
   end)
   return ok,info
end
