local cell = require "cell"
local peer_ip,peer_port
local cfg,fd,role
cell.command {
	ping = function()
		cell.sleep(1)
		return "pong"
	end,
	sleep = function(T)
	      cell.sleep(T)
	      return true
	end,
	set_peer = function(...)
	   peer_ip,peer_port = ...
	   return true
	end
}
function cell.main(params,role1,fd)
   local params = {
      mode = "client",
      protocol = "dtlsv1",
      key = "./certs/client/key.pem",
      certificate = "./certs/client/cert.pem",
      cafile = "./certs/client/cacerts.pem",
--      verify = {"peer", "fail_if_no_peer_cert"},
--      options = {"all", "no_sslv2"}
   }

   cfg =  params
   role = role1
   return true
end


cell.message {
   start = function(peer_ip,peer_port)
      if role == "server" then
	 fd:dtls_listen(cfg,peer_ip,peer_port)
      else
	 fd:dtls_connect(cfg,peer_ip,peer_port)
      end
   end,
   accept_udp = function(msg,len,peer_ip,peer_port)
      --local obj=cell.bind(fd)
      --obj:write(p,peer_ip,peer_port)
      print("receive from ",peer_ip,peer_port)
   end
}