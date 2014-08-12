local cell = require "cell"
local ws_server = require "protocol.ws_server"
local socket
local server  
local json = require "cjson"
local users ={}
local meetings = {}
local id = 1000000
local function get_id()
   id = id + 1
   return id
end
local db_imp
local meeting_manager
local user_name
cell.message{
   join_meeint = function(user)
      local rep = {
	 stream="presence",
	 id="1",
	 from=user,
	 to=user_name,
	 type="join_meeting",
	 body= {
	    show = "chat",
	    status = "Bored out of my mind",
	    priority = "1"
	 }
      }
      server:send_text(json.encode(rep))
   end,
   chat = function(user,msg)
      local rep = {
	 stream= "message",
	 id= get_id(),
	 from= user,
	 to= user_name,
	 type= "chat",
	 body= msg
      }
      server:send_text(json.encode(rep))
   end
}
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

local  handle = {
   text = function(msg)
      local req = json.decode(msg)
      local rep
      if req.type == "list_meeting" then
	 local mts
	 local mts = cell.call(db_imp,"list_meeting") 
	 rep = {
	    stream= "iq",
	    id= req.id,
	    from= req.from,
	    to= req.to,
	    type= "result",
	    body = mts
	 }
	 server:send_text(json.encode(rep))
      elseif req.type == "create_meeting" then
	 local mt_no = cell.call(db_imp,"create_meeting",req.body)
	 local rep = {
	    stream="iq",
	    id=req.id,
	    from = req.from,
	    to = req.to,
	    type = "result",
	    body = {
	       meeting_no =  mt_no
	    }
	 }	 
	 server:send_text(json.encode(rep))
      elseif req.type == "join_meeting" then
	 local r,service = cell.call(meeting_manager,"join_meeting",req.body,user)
	 assert(r)
--	 meeting_service[req.body.meeting_no] = service
	 local rep = { 
	    stream="iq",
	    id=req.id,
	    from = req.from,
	    to = req.to,
	    type = "result",
	    body = ""
	 }	 
	 server:send_text(json.encode(rep))
      elseif req.type == "answer" or req.type == "offer" then
	 local r,msg = cell.call(meeting_manager,req.type,req.body)
	 assert(r)
	 local t1 = {answer = "offer",offer = "answer"}
	 local rep = { 
	    stream="iq",
	    id=req.id,
	    from = req.from,
	    to = req.to,
	    type = t1[req.type],
	    body = msg
	 }	 
	 server:send_text(json.encode(rep))
      else
	 rep = {error="test"}
      end
      --rep = json.encode(rep)
      --server:send_text(rep)
   end  
}
function cell.main(...)
   db_imp,meeting_manager = ...
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
