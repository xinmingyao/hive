local cell = require "cell"
local peer_port
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
function cell.main()
   local params = {
      mode = "server",
      protocol = "dtlsv1",
      key = "./certs/server/key.pem",
      certificate = "./certs/server/cert.pem",
      cafile = "./certs/server/cacerts.pem",
      verify = {"peer", "fail_if_no_peer_cert"},
      options = {"all", "no_sslv2"}
   }
   local fd = cell.open(9998,cell.self)
   print(fd:dtls_listen(params))

   return true
end

cell.message {
    accept_udp = function(msg,len,peer_ip,peer_port)
      --local obj=cell.bind(fd)
      --obj:write(p,peer_ip,peer_port)
      print("receive from ",peer_ip,peer_port)
   end
}