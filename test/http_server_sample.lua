local cell = require "cell"
local ws_server = require "http.http_server"
local socket
local server  
local  handle = function(code, url, method, header, body)
   --   for k,v in pairs(header) do
   --      print(k,v)
   --   end
   print("receive:",header["Content-Type"])
   return 200,{["Content-Type"]="text/plain"},"hello,world"
end
function cell.main(fd)
   cell.timeout(0,function()
		   server,err = ws_server.new(fd,handle)
   end)
end
