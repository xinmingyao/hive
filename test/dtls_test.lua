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

function cell.main(...)
   local server_port,client_port = ...
   assert(server_port and client_port)
   local server = cell.cmd("launch", "test.dtls_server",server_port)
   local client = cell.cmd("launch", "test.dtls_client",client_port)
   cell.call(server,"set_peer_port",client_port)
   cell.call(client,"set_peer_port",server_port)
   cell.send(client,"start")
   print("pingpong launched",gui[1])
   return msg
end
