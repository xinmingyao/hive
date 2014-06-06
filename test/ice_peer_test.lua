local cell = require "cell"
local client --= require "test.ice_peer_client"
local server --= require "test.ice_peer_server"
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
   print("peer test launched")
   local remote_info
   client,ok,remote_info = cell.cmd("launch", "test.ice_peer_client",9001)
   print(remote_info[1].locals[1].priority)
--   server,ok,server_info = cell.cmd("launch", "test.ice_peer_client",9002,remote_info)
--   cell.call(client,"set_remotes",server_info)
--   cell.call(client,"ping")
   return 
end
