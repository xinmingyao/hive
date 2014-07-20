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
	   return peer:set_remotes(...)
	end,
	ping = function()
	   peer:send(sid,cid,"12345678")
	   peer:send(sid,cid,"ping")
	   --assert(pong == "pong")
	end
	
}

cell.message {
   receive = function(sid,cid,msg,sz)
      local pos,data = bin.unpack("A"..sz,msg,sz)
      print("client receive:",data)
   end
}

function cell.main(port)
   
   if not port  then
      port = 9000
   end
   print("client start:",port)
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
      mode = "server",
      protocol = "dtlsv1",
      key = "./certs/server/key.pem",
      certificate = "./certs/server/cert.pem",
      cafile = "./certs/server/cacerts.pem",
      verify = {"peer", "fail_if_no_peer_cert"},
      options = {"all", "no_sslv2"}
   }
   local opts = {dtls=true,dtls_config=cfg}
   peer = ice_peer.new(streams_info,stun_servers,opts)
   local ok,info = peer:offer()
   return ok,info
end
