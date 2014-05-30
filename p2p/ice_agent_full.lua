local bit = require "bit32"
local math = require "math"
local stun = require "p2p.stun1"
local streams_info,stun_servers,opts
local role
local local_streams = {}
local remote_streams
local tie_break = math.random(1,bit.lshift(1,20))

local gather_tx = {}
local check_tx ={}

local socket_info = {}
local start_ev
local state
local candi_id = 1
local pair_id = 1
local tx_id = 1
local pair_id = 1
local ta = 20 -- timeout for gather and check
local max_count = 3
local que_meta = {}

local function new_que()
   local q = {count=0,data={}}
   return setmetatable(q,{__index=que_meta})
end

function que_meta:append(v)
   table.insert(self.data,v)
end
function que_meta:is_que_empty()
   return self.count > #(self.data)
end
function que_meta:pop()
   local count = self.count
   self.count = count + 1
   return self.data[count]
end
local function is_gather_que_empyt()
   return gather_que.count > #(gather_que)
end

local trigger_que = new_que()
local gather_que = new_que()
local function pop_gather_que()
   local count  = gather_que.count
   gather_que.count = count + 1
   return gather_que[count]
end
local function deep_copy(src,dst)
   local k,v
   for k,v in dst do
      if type(v) == "table" then
	 local v1 = {}
	 deep_copy(v1,v)
	 src.k = v1
      else
	 src.k = v
      end
   end
   local i
   for i in #dst do
      local v = dst[i]
      if type(v) == "table" then
	 local v1 = {}
	 deep_copy(v1,v)
	 src[i] = v1
      else
	 src[i] = v
      end
   end
end

local function del_redudant()
   local i
   for i=1 ,#local_streams do
      local stream = local_streams[i]
      local j = 1
      local locals = stream.locals
      local num1 = #(locals)
       while j<=num1  do
	 local c = stream.locals[j]
	 local k = 1
	 local num2 = #(locals) 
	 for k=1,num2 do
	    local c1 = stream.locals[k]
	    if c.addr.ip == c1.addr.ip and c.addr.port == c1.addr.port and c.priority<c1.priority then
	       table.remove(locals,j)
	       j = j-1
	       num = num -1
	    end
	 end
	 j = j+1
       end
   end
end
--same type network has same fid
local function compute_candidate_fid()
   local fids = {}
   local i
   for i=1 , #local_streams do
      local stream = local_streams[i]
      local locals = stream.locals
      for j=1 , #locals do
	 local c = locals[j]
	 local key 
	 if c.type == "CANDIDATE_TYPE_RELAYED" then
	    key = c.transport .. c.type ..c.stun_server.ip
	 else
	    key = c.transport .. c.type ..c.ip
	 end
	
	 local fid
	 if fids.key then
	    fid = fids.key
	 else
	    fid = math.random(1,bit.lshift(1,20))
	 end
	 c.fid = fid
      end
   end
end

local function do_sort()
   local i
   for i=1 , #local_streams do
      local stream = local_streams[i]
      local locals = stream.locals
      table.sort(locals,function(c1,c2)
		    return c1.priority > c2.priority
      end)
   end
end
local function do_gather_complete()
   del_redudant()
   compute_candidate_fid()
   do_sort()
end

local function is_gather_complete()
   if #gather_tx == 0 and is_gather_que_empyt() then
      state = "running"
      do_gather_complete()
      cell.resume(start_ev)
   end
end
local function do_gather(cmd,...)
      local fsm = {
	 gather =function()	    
	    if is_gather_que_empyt() then
	       return
	    end
	    local gather = pop_gather_que()
	    gather_tx[tx_id] = {count=1,gather = gather}
	    tx_id = tx_id +1
	    local req = stun.new("request","binding",tx_id)
	    local data = req:encode()
	    local s = gather.c.socket
	    s:write(data,gather.stun_ip,gather.stun_port)
	    cell.timeout(ta,function()
			    cell.send(cell.self,"gather_rto",tx_id)
	    end)
	 end,
	 gather_rto = function(tid)
	    if gather_tx[tid] then
	       local count = gather_tx[tid].count
	       if count > max_count then
		  gather_tx[tid] = nil
		  is_gather_complete()
		  return 
	       end
	       count = count + 1
	       gather_tx[tid].count = count
	       local gather = gather_tx[tid].gather
	       local req = stun.new("request","binding",tid)
	       local data = req:encode()
	       local s = gather.c.socket
	       s:write(data,gather.stun_ip,gather.stun_port)
	       cell.timeout(ta,function()
			       cell.send(cell.self,"gather","gather_rto",tid)
	       end)
	    end
	 end,
	 stun = function(req)
	    if gather_tx[req.tx_id] then
	       local gather = gather_tx[req.tx_id].gather
	       local host = gather.c
	       local addr  = req.attrs['XOR-MAPPED-ADDRESS']
	       local ip,port = addr.ip,addr.port
	       local c = {type="CANDIDATE_TYPE_SERVER_REFLEXIVE",
			  transport = "udp",
			  addr = {ip=ip,port=port},
			  base_addr = {ip = host.addr.ip,port= host.addr.port},
			  cid = host.cid,
			  sid = host.sid,
			  user = host.user,
			  pwd = host.pwd}	       
	       table.insert(local_streams[sid].locals,c)
	       is_gather_complete()
	    end
	 end
      }
      fsm[cmd](...)   
end 

local function do_running()
end
local function do_completed()
end
local function do_failed()
end
local states = {
   gather = do_gather,
   running = do_running,
   completed = do_completed,
   failed = do_failed
}



local function build_host()
   local i
   for i in #(streams_info) do
      local stream = streams_info[i]
      local cps = stream.componets
      local j
      local_streams[i].sid = stream.sid
      local_streams[i].locals = {}
      for j in #(cps) do
	 local c = cps[j]
	 local socket = cell.open(c.port,cell.self)
	 local id = candi_id
	 candi_id = candi_id +1
	 local candidate = {
	    id = id,
	    type = "CANDIDATE_TYPE_HOST",
	    transport = "udp",
	    addr = {ip=c.ip,port=c.port},
	    socket = socket,
	    cid = c.cid,
	    user = c.user,
	    pwd = c.pwd,
	    sid = stream.sid }
	 socket_info[socket] = candidate
	 table.insert(local_streams[i].locals,candidate)
      end
   end
end
local function build_gather_que()
   local i 
   local stun = stun_servers[1] -- only one stun server in this version
   for i in #(locals) do
      table.insert(gather_que,{c=locals[i],stun_ip=stun.ip,stun_port=stun.port})
   end
   gather_que.count = 1
end
cell.command {
   start = function(...)
      role = ...
      state = gather
      cell.send(cell.self,"gather","gather")
      start_ev = cell.event()
      cell.wait(ev)
      return local_streams
   end,
   sleep = function(T)
      cell.sleep(T)
      return true
   end
}
local gatherF = function(...)
   if states["gather"] then
	 states["gather"](...)
   end
end

local function build_pair()
   local i
   for i=1,#local_streams do
      stream = local_streams[i]
      stream.checklist = {}
      local l2 = deep_copy(stream.locals)
      local j=1
      --remove not host candidate
      while j<=#l2 do
	 if l2[j].type ~= "CANDIDATE_TYPE_HOST" then 
	    table.remove(l2,j)
	    j = j-1
	 end
      end
      
      for j=1,#l2 do
	 local k
	 local c1 = l2[j]
	 for k=1,#(remote_streams[i].locals) do 
	    local c2 = remote_streams[i].locals
	    if c1.cid == c2.cid then
	       local pair = {id=pair_id,fid=""..c1.fid..c2.fid,l=c1,r=c2,
			     state = "pair_frozen",
			     sid = c1.sid,
			     cid = c1.cid
	       }
	       table.insert(stream.checklist,pair)
	       pair_id = pair_id + 1
	    end
	 end
      end
   end
end

local function compute_pair_priority(pair)
   local p,max,min,v
   local p1 = pair.l.priority
   local p2 = pair.r.priority
   if p1 > p2 then
      max,min = p1,p2
   else
      max,min = p2,p1
   end
   if role == "contrlling" and p1 > p2 then
      v = 1
   else
      v = 0
   end
   return bit.lshift(1,32) * min + 2 * max +v
end
local function priority_checklist()
   local i
   for i=1,#local_streams do
      local stream = local_streams[i]
      local j
      for j=1,#stream.checklist do
	 local pair = stream.checklist[j]
	 pair.priority = compute_pair_priority(pair)
      end
   end
end
local function sort_checklist()
   local i
   for i=1,#local_streams do
      local stream = local_streams[i]
      table.sort(stream.checklist,function(paira,pairb)
		    return paira.priority > pairb.priority
      end)
   end
end

local function trigger_check(sid)
   
end

local function order_check(sid)
   local stream = local_streams[sid]
   local checklist = stream.checklist
   table.sort(checklist,function(pairA,pairB)
		 local state_v ={
		    PAIR_IN_PROGRESS = 0,
		    PAIR_COMPLETED = 0,
		    PAIR_FAILED = 0,
		    PAIR_FROZEN  = 1,
		    PAIR_WAITING = 2
		 }
		 if state_v[pairA.state] > state_v[pairB.state]  then
		    return true
		 elseif state_v[pairA.state] == state_v[pairB.state] then
		    if pairA.priority > pairB.priority then
		       return true
		    end
		 else
		    return false
		 end
   end)
   local c = checklist[1]
   if c.state == PAIR_WAITING or c.state == PAIR_FROZEN then
      --do send
   else
      
   end

end
local function check_timer(time,sid)
   assert(sid)
   local stream = local_streams[sid]
   if trigger_que:is_que_empty() then
      order_check(sid)
   else
      trigger_check(sid)
   end
   cell.timeout(time,function()
		   check_timer(time,sid)
   end)
end
local function start_check()
   local stream = local_streams[1]
   cell.timeout(ta,function()
		   check_timer(ta,stream.sid)
		   end
   )
end

local function form_checklist()
   build_pair()
   priority_checklist()
   sort_checklist()
   start_check()
end
local function  do_ice_handshake()
   form_checklist()
end
cell.message {
   gather = gatherF,
   gather_rto = gatherF,
   set_remotes = function(...)
      remote_streams = ...
      assert(remote_streams)
      assert(type(remote_streams) == "table")
      do_ice_handshake()
   end,
   accept_udp = function(msg,sz,peer_ip,peer_port)
      --todo peek msg
      local ok,req = stun.decode(msg,sz)
      if ok then
	 if states[state] then
	    states[state]("stun",req,peer_ip,peer_port)
	 end
      else
	 print("error",req)
      end
   end
}
function cell.main(...)
   streams_info,stun_servers,opts = ...
end
