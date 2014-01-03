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
   local sip_app = {port = 5060,id="1561300657",username="32020000001320000002"}
   local sip = cell.cmd("launch","protocol.sip",sip_app)
   assert(sip)
   cell.call(sip,"start")
   local from = "32020000001320000002@192.168.203.157"
   --print("message:",cell.call(sip,"message",cell.self,"test@192.168.203.157:5061","server@192.168.203.157","192.168.203.157",{}))
   print("message:",cell.call(sip,"register",cell.self,from,from,"34020000002000000001@192.168.203.157:5061",{}))
   return true
end
