local cell = require "cell"
local ws_server = require "protocol.ws_server"
local socket
local server  
local json = require "cjson"
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
local count =1
local function ta(t)
   count = count +1
   local rep = {
      stream= "message",
      id= "1",
      from= "1@test",
      to= "2@test",
      type= "chat",
      body= "hello world " .. count,
      subject="query"
   }
   
   rep = json.encode(rep)
   server:send_text(rep)
   cell.timeout(500,function()
		   ta(500)
   end)
		
end
local  handle = {
   text = function(msg)
      local req = json.decode(msg)
      local rep
      if req.type == "list_meeting" then
	 rep = {
	    stream= "iq",
	    id= "1",
	    from= "1@test",
	    to= "2@test",
	    type= "result",
	    body = {
	       {
		  name= "test",
		  host_name= "admin",
		  create_time= "2014-01-01 56=80",
		  statue= 0
	       },
	       {
		  name= "test2",
		  host_name= "admin",
		  create_time= "2014-01-01 56=80",
		  statue= 0
	       }
	    }
	 }
      elseif req.type == "create_meeting" then
	 rep = {error="test"}
      else
	 rep = {error="test"}
      end
      rep = json.encode(rep)
      server:send_text(rep)
      ta(500)
   end  
}
function cell.main(fd)
   cell.timeout(0,function()
		   server,err = ws_server.new(fd,handle)
		   if server then
		      return true
		   else
		      print("error",err)
		      return false
		   end
   end)
end
