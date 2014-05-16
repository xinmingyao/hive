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
      mode = "server",
      protocol = "dtlsv1",
      key = "./certs/server/key.pem",
      certificate = "./certs/server/cert.pem",
      cafile = "./certs/server/cacerts.pem",
      verify = {"peer", "fail_if_no_peer_cert"},
      options = {"all", "no_sslv2"}
   }
   local fd = cell.open(9001)
   print(fd:dtls_listen(params))

   return true
end
