local cell = require "cell"
function start_server()
   print(cell.listen("192.168.203.157:8089",function(fd,msg)
			local s = cell.cmd("launch", "test.http_server_sample",fd)
			return s
   end))
end
function cell.main()
   --ws_proto.parse_test()
   start_server()
   return 
end
