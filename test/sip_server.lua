local cell = require "cell"
local sip_parser = require "protocol.sip_parser"
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

local sip_app = {local_uri = "192.168.203.157:5061",port = 5061,id="server",username="test",realm="340002"}
function cell.main()
   
   local sip = cell.cmd("launch","protocol.sip",sip_app)
   assert(sip)
   cell.call(sip,"start")
   cell.call(sip,"listen",cell.self)
   return true
end

local nonce = {}
local nonce_value = 1
cell.message {
   handle_sip =function(ok,req,handle)
      print("receive sip",ok,req,handle)
      local service = handle.service
      if ok then
	 if req.method == "REGISTER" then
	    if req.header["Authorization"] then
	       local ok1,auth = sip_parser.parse_auth(req.header["Authorization"])
	       if ok1 then
		  local one = auth.nonce
		  if nonce[tonumber(one)] then
		     cell.send(service,"reply",handle,{status = 200,header = {}})
		     return 
		  end
	       end
	    end
	    nonce_value = nonce_value +1
	    local h = {}
	    h["WWW-Authenticate"] = string.format("Digest realm=%s,nonce=%d",
						     sip_app.realm,nonce_value)
	    nonce[nonce_value] = true
	    cell.send(service,"reply",handle,{status = 401,header = h})
	 else
	    local rep = {status = 200,header={}}
	    cell.send(service,"reply",handle,rep)
	 end
      else
	 print("not ok message:",ok,req,handle)
      end
   end
}