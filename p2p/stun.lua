local cell = require "cell"
local logic_time
local timeA = 200 -- repeat send time
local timeB = timeA * 3 -- finish time
local stun_co
local stuns = {}
local parser = require "p2p.stun_parser"
local tx_id = 1
local service_channel = {}

function service_channel:write(req,ip,port)
   cell.send(self.service,"stun_rep",req,ip,port)
end

local function new_service_channel(service)
   local channel = {service = service}
   return setmetatable(channel,{__index = service_channel})
end

local function resume_co(tx,v)
   if stuns[tx] then
      local co = stuns[tx].co
      if co then
	 return coroutine.resume(co,v)
      end
   end
   return false
end

local function time_out(t,tx,v)
   cell.timeout(t,function()
		   resume_co(tx,v)
   end)
end

local function time_a(tx,v)
   time_out(timeA,tx,v)
end
local function time_b(tx,v)
   time_out(timeB,tx,v)
end

cell.message {
   udp = 
      function(msg,sz,peer_ip,peer_port)
	 local ok,rep = parser.paser_rep(msg,sz)
	 local k,v
	 for k,v in pairs(rep) do
	   --print(k,v)
	 end
	 local stun = stuns[rep.tx]
	 if stun then
	    local co = stun.co
	    local tt,ok,value = coroutine.resume(co,rep)
	    if ok == true or ok == false then
	       local task = stun.task	       
	       cell.resume_co(task,ok,value)
	    end
	 else
	    --flush
	 end
      end
}
   

local function stun_fsm(tx,...)
   assert(tx)
   local channel,local_ip,local_port,stun_ip,stun_port = ...
   local info = {}
   local stun_state = "init_test1"

   assert(local_ip and local_port and stun_ip and stun_port)
   --cell.set_socket_meta(channel) -- todo fix lua seri not copy meta ,so hand copy
   print(tx,channel,local_ip,local_port,stun_ip,stun_port)
   local req = parser.new_stun_req(tx)  
   local ok,bin = req:build_bin()

   channel:write(bin,stun_ip,stun_port)
   time_a(tx,"init_test1_timeoutA")
   time_a(tx,"init_test1_timeoutB")
  
   local fsm = 
      {
	 init_test1 = function(rep)
	    if type(rep) == "string" and rep == "init_test1_timeoutA" then
	       channel:write(bin,stun_ip,stun_port)
	       time_a(tx,"init_test1_timeoutA")
	       return
	    end
	    if type(rep) == "string" and rep == "init_test1_timeoutB" then
	       stun_state = "finish"
	       info.nat_type = "UDP_BLOCKED"
	       return true,info
	    end
	    if type(rep) ~= "table" then
	       --flush msg
	       print("flush msg",rep)
	       return
	    end

	    info.external_ip = rep.external_ip
	    info.external_port = rep.external_port
	    info.changed_ip = rep.changed_ip
	    info.changed_port = rep.changed_port
	    if info.local_ip == rep.external_ip then
	       time_a(tx,"ip_same_test2_timeoutA")	       
	       time_b(tx,"ip_same_test2_timeoutB")	       
	       stun_state = "ip_same_test2"
	    else
	       time_a(tx,"ip_diff_test2_timeoutA")
	       time_b(tx,"ip_diff_test2_timeoutB")
	       stun_state = "ip_diff_test2"
	    end

	    req = parser.new_stun_req(tx)

	    req:append_change_ipport()
	    ok,bin = req:build_bin()

	    channel:write(bin,stun_ip,stun_port)
	    return
	 end,
	 ip_same_test2 = function(rep)
	    if type(rep) == "string"  and rep == "ip_same_test2_timeoutA" then
	       channel:write(bin,stun_ip,stun_port)
	       time_a(tx,"ip_same_test2_timeoutA")	       
	       return 
	    end
	    if type(rep) == "string"  and rep == "ip_same_test2_timeoutB" then
	       stun_state = "finish"
	       info.nat_type = "SYSMETRIC_FIREWALL"
	       return true,info
	    end

	    if type(rep) ~= "table" then
	       --flush msg
	       print("flush msg:",rep)
	       return
	    end
	    info.nat_type = "OPEN_INTERNET"
	    return true ,info
	 end,
	 ip_diff_test2 = function(rep)
	    if type(rep) == "string"  and rep == "ip_diff_test2_timeoutA" then
	       channel:write(bin,stun_ip,stun_port)
	       time_a(tx,"ip_diff_test2_timeoutA")
	       return 
	    end
	    if type(rep) == "string" and rep =="ip_diff_test2_timeoutB" then
	       ok,bin = parser.new_stun_req(tx):build_bin()
	       channel:write(bin,info.changed_ip,info.changed_port)
	       stun_state = "ip_diff_test2_test1"
	       time_a(tx,"ip_diff_test2_test1_timeoutA")
	       time_b(tx,"ip_diff_test2_test1_timeoutB")
	       return 
	    end
	    if type(rep) ~= "table" then
	       --flush msg
	       print("flush msg:",rep)
	       return
	    end
	    info.nat_type = "FULL_CONE"
	    return true ,info
	 end,
	 ip_diff_test2_test1 = function(rep)
	    if type(rep) == "string"  and rep == "ip_diff_test2_test1_timeoutA" then
	       channel:write(bin,info.changed_ip,info.changed_port)
	       time_a(tx,"ip_diff_test2_test1_timeoutA")
	    end
	    
	    if type(rep) == "string"  and rep == "ip_diff_test2_test1_timeoutB" then
	       info.nat_type = "UDP_BLOCKED2" --FIX MAYBE NOT HAPPEN
	       return true,info
	    end

	    if type(rep) ~= "table" then
	       --flush msg
	       print("flush msg:",rep)
	       return
	    end
	    if info.external_ip ==  rep.external_ip and info.external_port == rep.external_port then
	       local attr = {}
	       attr.type = 0x0003
	       attr.length = 0x0004
	       attr.value = 0x0002
	       req = parser.new_stun_req(tx)
	       req:append_change_port()
	       ok,bin = req:build_bin()
	       channel:write(bin,stun_ip,stun_port)
	       time_a(tx,"test3_timeoutA")
	       time_b(tx,"test3_timeoutB")
	       stun_state = "test3"
	    else
	       stun_state = "finish"
	       info.nat_type = "SYSMETRIC_NAT"
	       return true,info
	    end
	 end,
	 test3 = function(rep)
	    if type(rep) == "string"  and rep == "test3_timeoutA" then
		  channel:write(bin,stun_ip,stun_port)
		  time_a(tx,"test3_timeoutA")	       
		  return 
	    end
	    if type(rep) == "string"  and rep == "test3_timeoutB" then
	       stun_state = "finish"
	       info.nat_type =  "RESTRIC_PORT_NAT"
	       return true,info
	    end
	    if type(rep) ~= "table" then
	       --flush msg
	       print("flush msg:",rep)
	       return
	    end
	    info.nat_type = "RESTRICTED_CONE"
	    return true ,info
	 end,
	 finish = function(rep)
	    --flush do nothine
	    print("flush in finish:",rep)
	 end
      }
   while true do
      local rep = coroutine.yield()
      --[[
	 local k,v 
	 if type(rep) == "table" then
	 for k,v in pairs(rep) do
	 print(k,v)
	 end
	 end
      ]]
      assert(fsm[stun_state])
      local ok,v = fsm[stun_state](rep)
      if stun_state == "finish" then
	 if type(rep) == "string" then --end by timeout
	    local task = stuns[tx].task
	    cell.resume_co(task,ok,v)
	 end
	 stuns[tx] = nil
	 return ok,v
      end
   end
end 

local function get_tx()
   tx_id = tx_id +1
   return tx_id
end



cell.command {
   start = function(service,local_ip,local_port,stun_ip,stun_port)
      local co =  coroutine.create(stun_fsm)
      local tx = get_tx()
      local stun = {tx=tx,co=co}
      local channel = new_service_channel(service)
      stuns[tx] = stun
      coroutine.resume(co,tx,channel,local_ip,local_port,stun_ip,stun_port)
      local task = cell.event()
      stun.task = task
      return cell.wait(task) --wait from uas
   end,
   get_accept = function(T)
      return nil
   end
}

function cell.main()
   cell.init()
   print("p2p stun launched")
   return true
end
