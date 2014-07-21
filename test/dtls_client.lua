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
function cell.main()
   local params = {
      mode = "client",
      protocol = "dtlsv1",
      key = "./certs/client/key.pem",
      certificate = "./certs/client/cert.pem",
      cafile = "./certs/client/cacerts.pem",
--      verify = {"peer", "fail_if_no_peer_cert"},
--      options = {"all", "no_sslv2"}
   }
   local port = 9998
   local fd = cell.open(9002,cell.self)
   --fd:write("hello world","127.",port)
   --fd:connect_udp("127.0.0.1",9998)
   print(fd:dtls_connect(params,"192.168.203.157",port))

   return true
end


cell.message {
    accept_udp = function(msg,len,peer_ip,peer_port)
      --local obj=cell.bind(fd)
      --obj:write(p,peer_ip,peer_port)
      print("receive from ",peer_ip,peer_port)
   end
}