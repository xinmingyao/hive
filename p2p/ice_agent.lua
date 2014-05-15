local cell = require "cell"
local socket
local au -- agent user service
local candidate = require "p2p.candidate"
local host,remote_candidates
local host_ip,host_port
local user,pwd
local component_id = 1
local stun_parser = "p2p.stun_parser"
local valid_candi
local check_list
local local_candidates
local stun_server_list
local ice_nat --nat info 
local default_candi
local trigged_check
local tx_session = {}

local timeA = 200 -- repeat send time
local timeB = timeA * 3 -- finish time
local stun_ip,stun_port
local function resume_co(tx,v)
   local task = tx_session[tx]
   if task then
      cell.resume_co(task,v)
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
   accept_udp = function(...)
      --deplux msg
      cell.send(stun,"udp",...)
      --cell.send(au,"udp",...)
      --do_ice
   end,
   stun_rep = function(...)
      socket:write(...)
   end
}

cell.command {
   ping = function()
      return "pong"
   end,
   sleep = function(T)
      cell.sleep(T)
      return true
   end
}
local tx_id = 1

local function get_tx()
   tx_id = tx_id +1
   return tx_id
end

local function gather_candi()
   local ok,ip,port = stun_agent()
   if ok then 
      return ok,get_server_reflexive_candidate(ip,port,component_id,host.transport,host.user,host.pwd)
   end
end
local function stun_agent()
   local tx = get_tx()
   local req = parser.new_stun_req(tx)  
   local ok,bin = req:build_bin()
   socket:write(socket,bin,stun_ip,stun_port)
   time_a(tx,"timeoutA")
   time_b(tx,"timeoutB")
   while ture do
      local task = cell.event()
      tx_session[tx] = task
      local ok,rep =  cell.wait(task)
      tx_session[tx] = nil
      if ok == true then
	 return ok,rep.external_ip,rep.external_port
      end
      if rep == "timeoutB" then
	 return ok,rep
      elseif rep == "timeoutA" then
	 socket:write(socket,bin,stun_ip,stun_port)
	 time_a(tx,"timeoutA")
      end
   end
end


local function new_candidate(ip,port,cid,transport,user,pwd)
   local host = candidate.new()
   host.type =  ctype
   if transport then
      host.transport = transport
   else
      host.transport = "UDP"
   end
   host.user = user
   host.pwd = pwd
   host.component_id = cid
   local priority = candidate.ice_priority_full(host.type,1,cid)
   host.priority = priority
   return host
end

local function get_host_candidate(ip,port,cid,transport,user,pwd)
   return new_candidate(ip,port,cid,transport,"PREF_HOST",user,pwd)
end

local function get_server_reflexive_candidate(ip,port,cid,transport,user,pwd)
   return new_candidate(ip,port,cid,transport,"PREF_SERVER_REFLEXIVE",user,pwd)
end

local function copy_table(src)
   local k,v
   local t = {}
   for k,v in pairs(src) do
      t[k] = v
   end
end
--ICE 5.7.3
local function pruning(candis)
   local local_copy = {}
   --copy and prune candi
   local k,v,count
   count = 1
   for k,v in ipairs(candis) do
      if not (v.ip == v.base_ip  and v.port == v.base_port) then
	 local_copy[count] = copy_table(v)
	 count = count + 1
      end
   end
end
local function start_ice()
   local_candidates = local_candidates or gather_candi()

   --ice 5.7.2
   table.sort(local_candidates,function(a,b)
		 return a.priority > b.priority
   end)

   local l_candi = pruning(local_candidates)
   
   table.sort(remote_candidates,function(a,b)
		 return a.priority > b.priority
   end)

   check_list = {}
   local k,v,k1,v1 
   for k,v in ipairs(l_candi) do
      for k1,v1 in ipairs(remote_candidates) do
	 table.insert(check_list,{l=v,r=v1,state="frozen"})
      end
   end
   
   local check_list = do_check_list()
end 

local function do_check_list(check_list)
   local k,v
   conn_check(v)
end
local tx_id = 0
local function get_tx()
   tx_id = tx_id +1
   return tx_id
end
local function conn_check(pair)
   local peer_ip,peer_port
   local tx = get_tx()
   local req = stun_parser.new_ice_req(tx)
   local user = pair[1].user
   local pwd = pair[1].pwd
   local priority = pair[1].priority
   local foundation = pair[1].fundation
   if user then
      req:append_user(user)
   end
   if pwd then
      req:append_pwd(pwd)
   end
   req:append_priority(priority)
   rq:append_foundation(foundation)
   
   peer_ip = pair[2].ip
   peer_port = pair[2].port
   local bin = req:build_bin()
 
   socket:write(peer_ip,peer_port,bin)
end

function cell.main(au,ip,port,remotes,c_id,opts)
   socket = cell.open(port,{protocol="p2p"})
   if socket then
      assert(remotes)
      
      cell.timeout(0,start_ice)
      return true
   else
      cell.exit()
      return false
   end
end
