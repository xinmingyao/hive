local cell = require "cell"
local ice_peer = require "p2p.ice_peer"
local peer
local sid = 1
local cid = 1
local bin = require "cell.binlib"
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
	   peer:send(sid,cid,"12345678")
	   --assert(pong == "pong")
	end
	
}

cell.message {
   receive = function(sid,cid,msg,sz)
      local pos,data = bin.unpack("A"..sz,msg,sz)
      print("server received:",data)
      peer:send(sid,cid,"12345678")

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
		cid=1,user="client",pwd="pwd1",port=port,ip="192.168.1.102"
	     }
	  }
	 }
      }
   local stun_servers =
      {
	 {ip="107.23.150.92",port=3478}
      }
   local cfg = {
      mode = "client",
      protocol = "dtlsv1",
      key = "./certs/client/key.pem",
      certificate = "./certs/client/cert.pem",
      cafile = "./certs/client/cacerts.pem",
      --      verify = {"peer", "fail_if_no_peer_cert"},
      --      options = {"all", "no_sslv2"}
   }
   local opts = {dtls=true,dtls_config=cfg}
   peer = ice_peer.new(streams_info,stun_servers,opts)
   local ok,info = peer:answer()
   cell.timeout(0,function()
		   peer:set_remotes(remotes)
   end)
   return ok,info
end
