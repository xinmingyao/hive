local cell = require "cell"
local sip_parser = require "protocol.sip_parser"
local hive_lib = require "hive.hive_lib"
local T1 = 500 -- ms
local timeA = 2 * T1
local timeB = timeA * 64
local timeD = timeA * 64
local timeE = 2 * T1
local timeF = timeE *64
local timeJ = timeF
local timeK = timeF
local sip_default_port = 5060
local socket
local txs = {}
local dialogs = {}
local transport = {}

local sip_transport = {}
local transport_meta = {
   __index = sip_transport
}

local branch = 1
local totag = 1
local sip_app --init by tu layer,must be table

local listen = {}

--[[
   ip
   port
   username
   realm
   local_uri
   id
--]]

local function get_session()
   session = session + 1
   return session
end



local function new_transport(socket)
   local obj = {socket=socket}
   return setmetatable(obj,transport_meta)
end

function sip_transport:write(req,ip,port)
   print("send data to =====:",ip,port,req)
   return socket:write(req,ip,port)
end

--local ok ,des_ip,des_port = sip_parser.get_des(req)

local function ack_uas(branch)
   local tx = txs[branch]
   local ok,req,ip,port
   if tx then
      local NH = build_header(method,branch,tx.from,tx.to,tx.headers)
      _,req = sip_parser.build_req("ACK",tx.uri,NH,tx.body)
      ok,ip,port = sip_parser.p_uri(tx.uri)
      assert(ok)
      transport:write(req,ip,port)
   end
end


local function rep_uac(branch,rep)
   local tx = txs[branch]
   local req = tx.req
   local via = req.header["Via"]
   local via_list = hive_lib.strsplit(",",via)
   local v1 = via_list[1] --reply use first via
   local h = {}
   local k,v
   for  k,v in pairs(rep.header) do
      h[k] = v
   end
   h["From"] = req.header["From"]
   h["To"] = req.header["To"]
   h["Via"] = string.format("SIP/2.0/UDP %s;branch=%s",sip_app.local_uri,branch)
   h["Call-ID"] = req.header["Call-ID"]
   h["SCeq"] = req.header["SCeq"]
   assert(v1)
   local ok,ip,port = sip_parser.get_via_addr(v1)
   local data 
   ok,data = sip_parser.build_rep(rep.status,h,rep.body)
   return transport:write(data,ip,port)
end


local function invite_client_tx()
   local branch
   local fsm
   local co_continue = coroutine.create(function(rep)
					   while true do 
					      local r = coroutine.yield("WAIT",branch)						 
					      fsm[txs[branch].state](rep)
					      if txs[branch].state == "terminated" then
						 txs[branch] = nil
						 return
					      end
					   end					   
   end)
   fsm = {
      init = function(rep)
	 if rep.method then --from tu
	    local ok,_ = transport:write(req)
	    if not ok then
	       txs[branch].state = "terminated"
	       return false,"transport error"
	    else
	       cell.timeout(timeA,function()
			       if txs[branch] then
				  local co = txs[branch].co
				  coroutine.resume(co,"timeout_a")
			       end
	       end)
	       cell.timeout(timeB,function()			       
			       if txs[branch] then
				  local co = txs[branch].co
				  coroutine.resume(co,"timeout_b")
			       end
	       end)
	       txs[branch].state = "calling"
	       return
	    end
	 end
      end,
      calling = function(rep)
	 if rep == "timeout_a" then
	    trasnport:write(txs[branch].req)
	    cell.timeout(timeA,function()
			    if txs[branch] then
			       local co = txs[branch].co
			       coroutine.resume(co,"timeout_a")
			    end
	    end)
	 end
	 if rep == "timeout_b" then
	    txs[branch].state = "terminated"
	    return false,"invite error,timeout "
	 end
	 if type(rep) ~= "table" then
	    return nil --donothing
	 end
	 if rep.status >=100 and rep.status <200 then
	    txs[branch].state = "proceeding"
	    cell.send(tu,"onexx",rep) --1xx to tu
	 elseif rep.status >=200 and rep.status <300 then
	    txs[branch].state = "terminated"
	    return true,rep	
	 elseif rep.status >=300 and rep.status<700 then
	    ack_uas(branch)     
	    txs[branch].state = "terminated"	    
	    txs[branch].co = co_continue
	    return ok,rep
	 end
      end,
      proceeding = function()
	 if type(rep) ~= "table" then
	    return nil
	 end
	 if rep.status >=100 and rep.status <200 then
	    cell.send(tu,"onexx",rep) --1xx to tu
	 elseif rep.status >=200 and rep.status <300 then
	    txs[branch].state = "terminated"
	    return true,rep	
	 elseif rep.status >=300 and rep.status<700 then
	    ack_uas(branch)     
	    txs[branch].state = "completed"	    
	    txs[branch].co = co_continue
	    return ok,rep
	 end
      end,
      completed = function()
	 if rep == "timeout_d" then
	    txs[branch].state = "terminated"
	 else
	    if type(rep) == "table" and rep.status >=300 and rep.status<700 then
	       local ok,info = ack_uas(branch)
	       if not ok then
		  txs[branch].state = "terminated"
		  return ok,info 
	       else
		  return true,rep
	       end
	    end
	 end
      end
   }
   
   while true do
      local rep,b = coroutine.yield()
      if b then
	 branch = b
      end
      assert(branch)
      local ok,rep = fsm[txs[branch].state](rep)
      if txs[branch].state == "terminated" then
	    txs[branch] = nil
      end
      if (ok ==true or ok == false) then --not nil conitune wait
	 return ok,rep
      end
   end
end

local function non_invite_server_tx(b,req)
   local branch
   local fsm,ok
   branch = b
   txs[branch].state = "init"
   fsm = {
      init = function(req)
	 cell.send(txs[branch].tu,"handle_sip",true,req,{service=cell.self,branch = branch})
	 txs[branch].state = "trying"
      end,
      trying = function(rep)
	 if rep.status >=100 and rep.status <200 then
	    rep_uac(branch,rep)
	    txs[branch].state = "proceeding"
	 elseif rep.status >=200 and rep.status <700 then
	    rep_uac(branch,rep)
	    txs[branch].state = "completed"
	 end
	 txs[branch].rep = rep
      end,
      proceeding = function(rep)
	 --from tu
	 if rep.status >=100 and rep.status <200 then
	    local ok = rep_uac(branch,rep)
	    if not ok then
	       txs[branch].state = "terminated"
	       cell.send(txs[branch].tu,false,"tx error")
	    end
	    txs[branch].rep = rep
	 elseif rep.status >=200 and rep.status <700 then
	    ok = rep_uac(branch,rep)
	    if not ok then
	       txs[branch].state = "terminated"
	       cell.send(txs[branch].tu,false,"tx error")
	    else
	       txs[branch].state = "completed"
	       cell.timeout(timeJ,function()
			       if txs[branch] then
				  local co = txs[branch].co
				  coroutine.resume(co,"timeout_j")
			       end
	       end)
	    end
	    txs[branch].rep = rep
	 end
	 if rep.method then --request
	    ok = rep_uac(branch,txs[branch].rep)
	    if not ok then
	       txs[branch].state = "terminated"
	       cell.send(txs[branch].tu,false,"tx error")
	    end
	 end
      end,
      completed = function(rep)
	 if rep == "timeout_j" then
	    txs[branch].state = "terminated"
	    return 
	 end
	 if rep.method then --request
	       ok = rep_uac(branch,txs[branch].rep)
	       if not ok then
		  txs[branch].state = "terminated"
		  cell.send(txs[branch].tu,false,"tx error")
	       end
	 end
      end
   }
   fsm[txs[branch].state](req)
   while true do
      local rep = coroutine.yield()
      assert(branch)
      assert(fsm[txs[branch].state])
      fsm[txs[branch].state](rep)
      if txs[branch].state == "terminated" then
	    txs[branch] = nil
	    return
      end
   end
end





local function non_invite_client_tx(req,b)
   local branch
   local fsm
   branch = b
   fsm = {
      init = function(req)
	 if type(req)== "string" then --from tu
	    local _,ip,port = sip_parser.p_uri(txs[branch].uri,5060)
	    transport:write(req,ip,port)
	    cell.timeout(timeE,function()
			    if txs[branch] then
			       local co = txs[branch].co
			       coroutine.resume(co,"timeout_e")
			    end
	       end)
	    cell.timeout(timeF,function()
			    local co = txs[branch].co
			    if txs[branch] then
				  coroutine.resume(co,"timeout_f")
			    end
	       end)
	    txs[branch].state = "trying"
	    return     
	 end
      end,
      trying = function(rep)
	 if rep =="timeout_e" then
	    trasnport:write(txs[branch].req)
	    cell.timeout(timeA,function()
			       if txs[branch] then
				  local co = txs[branch].co
				  coroutine.resume(co,"timeout_a")
			       end
	    end)
	 end
	 if rep == "timeout_f" then
	    txs[branch].state = "terminated"
	    return false,"tx timeout "
	 end
	 if type(rep) ~= "table" then
	    return nil --donothing
	 end
	 if rep.status >=100 and rep.status <200 then
	    txs[branch].state = "proceeding"
	    cell.send(tu,"onexx",rep) --1xx to tu
	 elseif rep.status >=200 and rep.status <700 then
	    txs[branch].state = "completed"
	    return true,rep	
	 end
      end,
      proceeding = function()
	 if rep =="timeout_e" then
	    trasnport:write(txs[branch].req)
	    cell.timeout(timeA,function()
			       if txs[branch] then
				  local co = txs[branch].co
				  coroutine.resume(co,"timeout_a")
			       end
	    end)
	 end
	 if rep == "timeout_f" then
	    txs[branch].state = "terminated"
	    return false,"tx timeout"
	 end
	 if type(rep) ~= "table" then
	    return nil
	 end
	 if rep.status >=100 and rep.status <200 then
	    cell.send(tu,"onexx",rep) --1xx to tu
	 elseif rep.status >=200 and rep.status<700 then
	    txs[branch].state = "completed"	    
	    cell.timeout(timeK,function()
			    txs[branch] = nil --
	    end)
	    return ok,rep
	 end
      end,
      completed = function()
	 if rep == "timeout_k" then
	    txs[branch].state = "terminated"
	 end
      end
   }
   
   local ok,rep = fsm[txs[branch].state](req)
   if txs[branch].state == "terminated" then
      txs[branch] = nil
   end
   if(ok ==true or ok == false) then --not nil conitune wait
      return ok,rep
   end
   while true do
      local rep = coroutine.yield()
      assert(branch)
      local ok,rep = fsm[txs[branch].state](rep)
      if txs[branch].state == "terminated" then
	    txs[branch] = nil
      end
      if(ok ==true or ok == false) then --not nil conitune wait
	 return ok,rep
      end
   end
end


local function get_branch()
   branch = branch +1
   return ""..branch
end 

local function get_totag()
   totag = totag +1
   return totag
end


local function get_req_info(dialog)
   local req = dialog.req
   local rep = dislog.rep
   local from = sip_parser.get_from(req)
   local to = sip_parser.get_to(req)
   local uri = sip_parser.p_uri(req.uri)
   local headers = {}
   local contack = sip_parser.get_contact(rep.header["Contact"])
   if contack then
      headers["Contact"] =  contack
   end
   -- routers  todo ---
   return from,to,uri,headers
end

local function build_header(method,branch,from,to,headers)
   assert(type(headers) == "table")
   assert(to and type(to)=="string")
   local h = {}
   local k,v
   for k,v in pairs(headers) do
      h[k] = v --copy k v
   end
   h["From"] = string.format("<sip:%s>;tag=%d",from,get_totag())
   h["To"] = string.format("<sip:%s>",to)
   local _,ip,port = sip_parser.p_uri(from)
   if port and port ~=5060 then 
      h["Via"] = string.format("SIP/2.0 %s:%s;branch=%d",ip,port,branch)
   else
      h["Via"] = string.format("SIP/2.0 %s;branch=%d",ip,branch)
   end
   h["Call-ID"] = sip_app.id
   h["CSeq"] = string.format("%d %s",1,method)
   h["Contact"] =  string.format("<sip:%s>",from)
   return h
end

local function start_server_tx(req)
   local branch
   local f 
   local method
   if method == sip_parser.method.INVITE then
      f = invite_server_tx 
   else 
      f = non_invite_server_tx
   end
   local _,branch = sip_parser.get_branch(req.header["Via"])
   assert(branch)
   local tx = {branch=branch,req=req,tu=listen.tu}
   local co = coroutine.create(f)    
   tx.co = co
   txs[branch] =  tx
   coroutine.resume(co,branch,req)
end

local function  wait_uas(method,tu,from,to,uri,headers,body)
   local ok,req,rep
   local f 
   if method == sip_parser.method.INVITE then
      f = invite_client_tx 
   else 
      f = non_invite_client_tx
   end
   local branch = get_branch()
   local NH = build_header(method,branch,from,to,headers)
   ok,req = sip_parser.build_req(method,uri,NH,body)
   if not ok then
      return false,"buidl req error"
   end
   local tx = {branch=branch,uri=uri,req=req,tu=tu,to=to,headers=headers}
   local co = coroutine.create(f)    
   tx.co = co
   tx.state = "init"
   txs[branch] =  tx
   local  _,ok,rep = coroutine.resume(co,req,branch)
   if  ok == false then --init call maybe trasnport error
      return ok,rep
   end
   local task = cell.event()
   tx.task = task
   return cell.wait(task) --wait from uas
end

cell.message {
   reply = function(handle,rep)
      local branch = handle.branch
      if txs[branch] then
	 local co = txs[branch].co 
	 coroutine.resume(co,rep)
      end
   end
}

local function accept_udp()
   local ok, data = sip_parser.parse_sip(socket)
   if not ok then
      print("parser error!!!!",data)
      return
   end
   if data.method then
      print("sip request:\r\n",select(2,sip_parser.build_req(data.method,data.uri,data.header,data.body)))
   else
      print("sip response:\r\n",select(2,sip_parser.build_rep(data.status,data.header,data.body)))
   end
   local _,branch  = sip_parser.get_branch(data.header["Via"])
   
   local tx = txs[branch]
   if data.status then -- rep
      if tx then
	 local _,ok,rep = coroutine.resume(tx.co,data)
	 if ok ~= nil then
	    cell.resume_co(tx.task,ok,rep)
	 end
      end
   else --req
      if tx then
	 coroutine.resume(tx.co,data)
      else
	 start_server_tx(data)
      end
   end
end

cell.command { --tu,to,uri,headers,body
   invite = function(...)
      local ok,rep = wait_uas("INVITE",...) --wait from uas
      if ok then
	 local dialog = {rep=rep}
	 local did = get_did(rep)
	 assert(did)
	 dialogs[did] =  dialog
	 return ok,r,did
      else
	 return ok,r
      end
   end,
   message = function(...)
      return wait_uas("MESSAGE",...)
   end,
   bye = function(tu,did)
      if not dialogs[did] then
	 return false,"dialog closed"
      else
	 
	 return wait_uas("BYE",get_req_info(dialogs[did]))
      end
   end,
   register = function(tu,from,to,uri,headers,body)
      --headers["Expires"] = "0"
      local ok,rep = wait_uas("REGISTER",tu,from,to,uri,headers,body)
      if not ok then
	 return ok,rep
      end
      if rep.status == 401 then
	 if rep.header["WWW-Authenticate"] then
	    local ok,auth = sip_parser.parse_auth(rep.header["WWW-Authenticate"])
	    assert(ok)
	    local response = "12345678"
	    headers["Authorization"] = string.format("Digest username=\"%s\",realm=%s,nonce=%s,uri=\"<sip:%s>\",response=\"%s\"",
						     sip_app.username,auth.realm,auth.nonce,uri,response)   
	    return wait_uas("REGISTER",tu,from,to,uri,headers,body)
	 else
	    return false,"cannot authenticate"
	 end 
      end
   end,
   start = function()
      socket = cell.open(sip_app.port,accept_udp,{protocol = "text"})
      if socket then
	 transport = new_transport(socket)
	 return true
      else
	 return false,"open udp error"
      end
   end,
   listen = function(tu)
      listen.tu = tu
   end
}




local function valide_app(app)
   if type(app) ~= "table" then
      return false ,"sip app must table"
   end
   
   if not app.username then
      return false,"must set username"
   end
   local k,v
   sip_app = {}
   for k,v in pairs(app) do --copy
      sip_app[k] = v
   end

   if not app.port then
      sip_app.port = 5060
   end  
   if not app.id then
      sip_app.id = "test"
   end
      
end


function cell.main(app)
   print(string.format("--------start sip at port %s --------",app.port))
   valide_app(app)
end
