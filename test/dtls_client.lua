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
      verify = {"peer", "fail_if_no_peer_cert"},
      options = {"all", "no_sslv2"}
   }
   local fd = cell.open(9002)
   print(fd:dtls_connect(params,"127.0.0.1",9001))

   return true
end
