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
local fd,db_imp
local meeting_manager,auth
local user_name
cell.message{
   list_user = function(users)
      local rep = {
	 stream="message",
	 id="1",
	 from=user,
	 to=user_name,
	 type="list_user",
	 body = users
      }
      server:send_text(json.encode(rep))
   end,
   join_meeting = function(join_user)
      local rep = {
	 stream="message",
	 id="1",
	 from=user,
	 to=user_name,
	 type="join_meeting",
	 body= join_user
      }
      server:send_text(json.encode(rep))
   end,
   chat = function(from,msg)
      local rep = {
	 stream= "message",
	 id= get_id(),
	 from= from,
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
      if req.type == "chat" then
	 cell.send(meeting_manager,"chat",req)
      elseif req.type == "auth" then
	 local ok,jid = cell.call(auth,"auth",req.body)
	 assert(ok)
	 rep = {
	    stream= "iq",
	    id= req.id,
	    from= req.from,
	    to= req.to,
	    type= "result",
	    body = {jid=jid}
	 }
	 user = jid
	 server:send_text(json.encode(rep))
      elseif req.type == "list_meeting" then
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
	 local mt_no = cell.call(db_imp,"create_meeting",user,req.body)
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
	 local r,service = cell.call(meeting_manager,"join_meeting",req.body,user,cell.self)
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
   fd,db_imp,meeting_manager,auth = ...
   cell.timeout(0,function()
		   server,err = ws_server.new(fd,handle)
		   if server then
		      print(server)
		      return true
		   else
		      print("error",err)
		      return false
		   end
   end)
end
