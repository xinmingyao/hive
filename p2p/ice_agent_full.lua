local bin = require "cell.binlib"
local cell = require "cell"
local bit = require "bit32"
local math = require "math"
local stun = require "p2p.stun1"
local ssl = require "ssl"
local lua_srtp = require "lua_srtp"
-- streams_info-->{sid,[{cid,ip,port,user,pws}]}
-- stun_servers-->[{ip,port}]
--opts --> {client,dtls,dtls_config}
local streams_info,stun_servers,opts
local role
local local_streams = {}
local remote_streams
local tie_break = math.random(1,bit.lshift(1,20))

local gather_tx = {}
local check_tx ={}

local socket_info = {}
local start_ev 
local set_remotes_ev
local state = "gather"
local candi_id = 1
local pair_id = 1
local tx_id = 1
local pair_id = 1
local ta = 20 -- timeout for gather and check
local max_count = 3 -- max timeout
local que_meta = {} 
local peer_pwd 
local seqno = math.random(0,bit.lshift(2,16))
local function get_seq()
   local old = seqno
   seqno = seqno +1
   return old
end
local function get_txid()
   local t = tx_id
   tx_id = tx_id + 1
   return t
end

local function get_pairid()
   local t = pair_id 
   pair_id = pair_id +1
   return t
end

local function get_candi_id()
   local t = candi_id 
   candi_id = candi_id + 1
   return t
end
local function new_que()
   local q = {count=1,data={}}
   return setmetatable(q,{__index=que_meta})
end

function que_meta:append(v)
   table.insert(self.data,v)
end

function que_meta:append_if_not_exist(v)
   local i 
   for i=self.count,#self do
      if v.id then 
	 if v.id == self[i].id then
	    return
	 end
      end
      if v.pair_id  then
	 if v.pair_id == self[i].pair_id then
	    return 
	 end
      end
   end
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

local function deep_copy(src,dst)
   
   local mt = getmetatable(dst)
   if mt then
      setmetatable(src,mt)
   end
   local k,v
   for k,v in pairs(dst) do
      if type(v) == "table" then
	 local v1 = {}
	 deep_copy(v1,v)
	 src[k] = v1
      else
	 src[k] = v
      end
   end
   local i
   for i in ipairs(dst) do
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



local function get_pair_by_id(sid,pair_id)
   local pairs = local_streams[sid].checklist
   local i
   for i=1,#pairs do
      if pair_id == pairs[i].id then
	 return pairs[i]
      end
   end
   assert(false,"should not happen!")
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


local function compute_candidate_priority(t,cid)
   local type_value = {
      CANDIDATE_TYPE_HOST = 120,
      CANDIDATE_TYPE_PEER_REFLEXIVE = 110,
      CANDIDATE_TYPE_SERVER_REFLEXIVE = 100,
      CANDIDATE_TYPE_RELAYED = 60
   }
   assert(type_value[t])
   return bit.lshift(1,24) * type_value[t] + bit.lshift(1,8) * 1 + 1*(256-cid) 
end


local function cancel_checklist(sid,pair)
   local checklist = local_streams[sid].checklist
   local i
   for i=1,#checklist do
      local p1 = checklist[i]
      if pair.cid == p1.cid and pair.id ~= p1.id then
	 -- do nothing
	 p1.state = "PAIR_CANCELLED"
      end
   end
end

local function update_checklist_state(sid)
   local checklist = local_streams[sid].checklist
   local i
   for i=1,#checklist do
      local pair = checklist[i]
      if pair.state == "PAIR_IN_PROGRESS" or pair.state == "PAIR_WAITING" or pair.state == " PAIR_FROZEN" then
	 -- do nothing
	 return
      end
   end
   
   local componets = streams_info[sid].components
   local tmp = {}
   for i = 1,#componets do
      local cid = componets[i].cid
      local j
      local validlist = local_streams[sid].validlist
      for j=1 ,#validlist do
	 if validlist[j].cid == cid then
	    table.insert(tmp,cid)
	 end
      end
   end
   
   if #tmp == #componets then
      local_streams[sid].checklist_state = "CHECKLIST_COMPLETED"
   else
      local_streams[sid].checklist_state = "CHECKLIST_FAILED"
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
	 local k 
	 for k = 1,#(locals)  do
	    local c1 = stream.locals[k]
	    if c.addr.ip == c1.addr.ip and c.addr.port == c1.addr.port and c.priority<c1.priority then
	       table.remove(locals,j)
	       j = j-1
	       num1 = num1 -1
	       break
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
      local j
      for j=1 , #locals do
	 local c = locals[j]
	 local key 
	 if c.type == "CANDIDATE_TYPE_RELAYED" then
	    key = c.transport .. c.type ..c.stun_ip
	 else
	    key = c.transport .. c.type ..c.addr.ip
	 end
	
	 local fid
	 if fids.key then
	    fid = fids.key
	 else
	    fid = math.random(1,bit.lshift(1,20))
	    fids.key = fid
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
   if #gather_tx ~= 0 then
      return 
   end
   local i
   for i=1,#local_streams do
      local que = local_streams[i].gather_que
      if not que:is_que_empty() then
	 return
      end
   end
   state = "running"
   do_gather_complete()
   cell.wakeup(start_ev)
end

local function do_gather(req)
   if gather_tx[req.tx_id] then
      local gather = gather_tx[req.tx_id].gather
      local host = gather.c
      local addr  = req.attrs['XOR_MAPPED_ADDRESS']
      local ip,port = addr.ip,addr.port
      local c = {type="CANDIDATE_TYPE_SERVER_REFLEXIVE",
		 transport = "udp",
		 addr = {ip=ip,port=port},
		 base_addr = {ip = host.addr.ip,port= host.addr.port},
		 cid = host.cid,
		 sid = host.sid,
		 user = host.user,
		 priority = compute_candidate_priority("CANDIDATE_TYPE_SERVER_REFLEXIVE",host.cid),
		 pwd = host.pwd,
		 stun_ip = gather.stun_ip,
		 stun_port = gather.stun_port
      }	       
      print("xor-mapping-address",ip,port)
      table.insert(local_streams[host.sid].locals,c)
      gather_tx[req.tx_id] = nil
      is_gather_complete()
   end
end 



local function do_send_check(pair,tid)
   local sid = pair.sid
   local priority = compute_candidate_priority("CANDIDATE_TYPE_SERVER_REFLEXIVE",pair.cid)
   local req = stun.new("request","binding",tid)
   req:add_attr('PRIORITY',priority)
   req:add_attr('USERNAME',pair.r.user ..":".. pair.l.user)
   req:add_attr('PASSWORD',pair.r.pwd)
   if role == "controlling" then
      if pair.is_nominate then
	 req:add_attr('USE_CANDIDATE',1)
      end
      req:add_attr('ICE_CONTROLLING',tie_break)
   else
      req:add_attr('ICE_CONTROLLED',tie_break)
   end
   req.key = peer_pwd
   local data = req:encode()
   local socket = pair.l.socket
   socket:write(data,pair.r.addr.ip,pair.r.addr.port)
end


local function nominate_rto_timer(time,txid)
   local tx = check_tx[txid]
   if not tx then
      return 
   end
   local index = tx.index
   local pair = local_streams[tx.sid].validlist[index]
   if tx.count > 3 then
      --should not happen 
      assert(false,"nominate error!")
   else      
      do_send_check(pair,txid)
      tx.count = tx.count +1
      cell.timeout(time,function()
		      nominate_rto_timer(time,txid)
      end)
   end
end

local function regula_nominate_timer(time,sid)
   local que = local_streams[sid].nominate_que
   if que:is_que_empty() then
      return
   else
      local index = que:pop()
      local pair = local_streams[sid].validlist[index]
      local tid = get_txid()
      check_tx[tid] = {sid=sid,index= index,count=1,is_nominate=true}
      pair.is_nominate = true
      do_send_check(pair,tid)
      cell.timeout(ta,function()
		    regula_nominate_timer(time,sid)
      end)
      cell.timeout(ta,function()
		    --nominate_rto_timer(ta,tid)
      end)
   end
end

local function start_regula_nominate(sid)
   if local_streams[sid].checklist_state == "CHECKLIST_COMPLETED" then
      if local_streams[sid].regula_nominate then
	 return 
      end
      local_streams[sid].regula_nominate = true

      local que = new_que()
      local_streams[sid].nominate_que  = que
      local validlist = local_streams[sid].validlist
      local i
      for i = 1,#validlist do
	 que:append(i)
      end
      cell.timeout(0,function()
		    regula_nominate_timer(ta,sid)
      end)
   end
end

local function is_agent_succeed()
   local i
   local failed = true
   if state == "completed" or state =="failed" then
      return 
   end
   for i =1 ,#local_streams do
      if local_streams[i].checklist_state ~= "CHECKLIST_FAILED" then
	 failed = false
	 break
      end
   end
   if failed then
      state = "failed"
      cell.wakeup(set_remotes_ev,true,state)
      return
   end
   
   for i = 1 ,#local_streams do
      if local_streams[i].checklist_state == "CHECKLIST_RUNNING" then
	 return 
      end
   end

   for i = 1,#local_streams do
      if local_streams[i].checklist_state == "CHECKLIST_COMPLETED" then
	 local validlist = local_streams[i].validlist
	 local j
	 for j=1 ,#validlist do
	    if not validlist[j].is_nominate then
	       return 
	    end
	 end
      end
   end

   if opts.dtls then
      local i
      for i =1 ,#local_streams do
	 if local_streams[i].checklist_state == "CHECKLIST_COMPLETED" then --not for failed component
	    local validlist = local_streams[i].validlist
	    local j
	    for j=1,#validlist do
	       local pair = validlist[j]
	       local socket = pair.l.socket
	       local r,msg
	       local cfg = opts.dtls_config
	       assert(cfg)
	       if role == "controlling" then
		  r,ssl_socket = socket:dtls_listen(cfg,pair.r.addr.ip,pair.r.addr.port)
	       else
		  print("begin connect",role)
		  r,ssl_socket  = socket:dtls_connect(cfg,pair.r.addr.ip,pair.r.addr.port)
	       end
	       if r then
		  print("----",r,ssl)
		  lua_srtp.srtp_init()
		  local srtp = lua_srtp.new()
		  local send_key,receiving_key =  ssl_socket:dtls_session_keys()
		  --print("keys:",string.len(send_key),string.len(receiving_key))
		  if role =="controlling" then
		     lua_srtp.set_rtp(srtp,receiving_key,send_key)
		  else
		     lua_srtp.set_rtp(srtp,send_key,receiving_key)
		  end
		  pair.srtp = srtp
		  pair.ssl = ssl_socket
	       else
		  print("error:",ssl_socket)
		  cell.wakeup(set_remotes_ev,false,"dtls_error")
		  --cell.send(opts.client,agent_fail,"dtls_error",ssl_socket)
	       end
	    end
	 end
      end
   end
   state = "completed"
   cell.wakeup(set_remotes_ev,true,state)
   return
end


local function do_running(req,fd,peer_ip,peer_port)
      if not set_remotes_ev then 
	 --flush the message
	 return 
      end

   if req.class =="error" then
      local tid = req.tx_id
      local tx = check_tx[tid]
      if not tx then 
	 return 
      end
      check_tx[tid] = nil
      local err_code = req:get_addr_value('ERROR-CODE')
      assert(err_code.number == 487) --todo other error
      if role == "controlling" then
	 role = "controlled"
      else
	 role = "controlling"
      end
      -- new role,recompute priority
      priority_checklist()
      sort_checklist()  

      local pair = get_pair_by_id(tx.sid,tx.pair_id)
      pair.state = "PAIR_WAITING"
      trigger_que:append({sid=tx.sid,pair_id=tx.pair_id})
      return 
   elseif req.class =="response" then
      local tid = req.tx_id
      local tx = check_tx[tid]
      check_tx[tid] = nil
      if not tx then
	 return
      end
      if role == "controlling" and tx.is_nominate then
	 local validlist = local_streams[tx.sid].validlist
	 local i
	 for i = 1,#validlist do
	    if tx.index == i then
	       validlist[i].is_nominate = true
	       break
	    end
	 end
      else
	 local pair = get_pair_by_id(tx.sid,tx.pair_id)
	 local validpair = {}
	 --rfc 7.1.3.2
	 local addr = req:get_addr_value('XOR_MAPPED_ADDRESS')
	 if addr.ip == pair.l.addr.ip and addr.port == pair.l.addr.port then
	    deep_copy(validpair,pair)
	 else -- peer flex
	    local priority = req:get_addr_value('PRIORITY')
	    c1 = {
	       id= get_candi_id(),
	       fid=pair.l.fid,
	       priority = priority,
	       type = "CANDIDATE_TYPE_PEER_REFLEXIVE",
	       transport = "udp",
	       addr= {ip=addr.ip,port=addr.port},
	       base_addr = {ip=pair.l.base_addr.ip,port = pair.l.base_addr.port},
	       socket = pair.l.socket,
	       cid = pair.l.cid,
	       sid = pair.l.sid,
	       user = pair.l.user,
	       pwd = pair.l.pwd
	    }
	    table.insert(local_streams[tx.sid].locals,c1)
	    --local remote = {}
	    --deep_copy(remote,pair.r)
	    deep_copy(validpair,pair)--{id = pair_id,l=c1,r=remote,cid=pair.cid,sid=pair.sid}
	    validpair.l = c1 
	    validpair.id = get_pairid()
	    validpair.priority = compute_pair_priority(validpair)
	 end

	 table.insert(local_streams[tx.sid].validlist,validpair)
     
	 pair.state = "PAIR_COMPLETED"
	 cancel_checklist(tx.sid,pair)
	 update_checklist_state(tx.sid)
	 
	 if role == "controlling" then
	    start_regula_nominate(tx.sid)
	 end
	 
      end
      is_agent_succeed()
   elseif req.class == "request" and req.method == "binding" then
      local conflict = false
      local role_change = false
      local use_candidate = req:get_addr_value('USE_CANDIDATE')
      if role == "controlling" then
	 if req:get_addr_value('CONTROLLING') then
	    if 	tie_break >  req:get_addr_value('CONTROLLING') then
	       conflict = true
	    else
	       role_change = true
	       role = "controlled"
	    end
	 end
      else
	 if req:get_addr_value('CONTROLLED') then
	    if tie_break > req:get_addr_value('CONTROLLED') then
	       conflict = true
	    else
	       role_change = true
	       role = "controlling"
	    end
	 end
      end
      
      local c = socket_info[fd]
      local socket = c.socket
      
      if conflict then
	 local rep = stun.new('error','binding',req.tx_id)
	 rep:add_attr('ERROR-CODE',{number=487,reason="role conflict",reserve=0,class=0})
	 local data = rep:encode()
	 socket:write(data,peer_ip,peer_port)
	 return	 
      end
      if role_change then
	 priority_checklist()
	 sort_checklist()
      end
      
      local rep = stun.new('response','binding',req.tx_id)
      local priority = req:get_addr_value('PRIORITY',priority)
      rep:add_attr('XOR_MAPPED_ADDRESS',{ip=peer_ip,port=peer_port})
      rep:add_attr('PRIORITY',priority)
      local data = rep:encode()
      socket:write(data,peer_ip,peer_port)
      -- find peer flex
      local i 
      local new_remote = true
      local pair 
      local checklist = local_streams[c.sid].checklist
      for i=1 ,#checklist do
	 local t = checklist[i]
	 local candidate = t.r
	 if peer_ip == candidate.addr.ip and peer_port == candidate.addr.port then
	    new_remote = false
	    pair = t
	    break
	 end
      end
      if new_remote then
	 local newcandi = {
	    id = get_candi_id(),
	    type = 'CANDIDATE_TYPE_PEER_REFLEXIVE' ,
	    priority = req:get_addr_value('PRIORITY'),
	    addr = {ip = peer_ip,port=peer_port},
	    cid = c.cid,
	    sid = c.sid,
	    fid =  math:random(1,bin.lshift(1,20))
	 }
	 local remotes = remote_streams[c.sid].locals
	 table.insert(remotes,new_remote)
	 local l = {}
	 deep_copy(l,c)
	 local pid = get_pairid()
	 local pair = {id=pid,sid=c.sid,cid=c.cid,l=l,r=newcandi,state = "PAIR_WAITING"}
	 pair.priority = compute_pair_priority(pair)
	 local que = local_streams[c.sid].trigger_que
	 que:append({sid=c.sid,pair_id = pid})
	 table.insert(local_streams[c.sid].checklist,pair)
      else
	 local state = pair.state
	 local que = local_streams[pair.sid].trigger_que
	 if use_candidate and role == "controlled" then
	    pair.is_nominate = true 
	 end
	 if state == "PAIR_IN_PROGRESS" then
	   -- pair.state = "PAIR_WAITING"
	   -- que:append_if_not_exist({sid=pair.sid,pair_id=pair.id})
	 elseif state == "PAIR_FROZEN" then
	    pair.state = "PAIR_WAITING"
	    que:append({sid=pair.sid,pair_id=pair.id})
	 elseif state == "PAIR_COMPLETED" then
	    if role == "controlled" and use_candidate then
	       local i
	       for i = 1, #local_streams[pair.sid].validlist do
		  local p2 = local_streams[pair.sid].validlist[i]
		  if p2.id == pair.id then
		     p2.is_nominate = true
		     break
		  end
	       end
	    end
	 elseif state == "PAIR_FAILED" then
	    pair.state = "PAIR_WAITING"
	    que:append({sid=pair.sid,pair_id=pair.id})
	 else -- waiting
	    pair.state = "PAIR_WAITING"
	    que:append({sid=pair.sid,pair_id=pair.id})
	 end
      end
      
      if role == "controlled" then
	 is_agent_succeed()
      end
      
   else
      assert(false,"not support!")
   end
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
   for i=1, #(streams_info) do
      local stream = streams_info[i]
      local cps = stream.components
      local j
      local_streams[i] = {}
      local_streams[i].sid = stream.sid
      local_streams[i].locals = {}
      local_streams[i].trigger_que = new_que()
      local_streams[i].validlist = {}
      for j=1, #(cps) do
	 local c = cps[j]
	 local socket = cell.open(c.port,cell.self)
	 local id = get_candi_id()
	 local candidate = {
	    id = id,
	    type = "CANDIDATE_TYPE_HOST",
	    transport = "udp",
	    addr = {ip=c.ip,port=c.port},
	    base_addr = {ip=c.ip,port=c.port},
	    socket = socket,
	    cid = c.cid,
	    user = c.user,
	    pwd = c.pwd,
	    priority = compute_candidate_priority("CANDIDATE_TYPE_HOST",c.cid),
	    sid = stream.sid }
	 socket_info[socket.__fd] = candidate
	 table.insert(local_streams[i].locals,candidate)
      end
   end
end


local function gather_rto_timer(time,tid)
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
      --req.fingerprint = false
      local data = req:encode()
      local s = gather.c.socket
      s:write(data,gather.stun_ip,gather.stun_port)
      cell.timeout(ta,function()
		      gather_rto_timer(time,tid)
      end)
   end
end
local function gather_timer(time,sid)
   local gather_que = local_streams[sid].gather_que
   if gather_que:is_que_empty() then
      return
   end
   local gather = gather_que:pop()
   local tid = get_txid()
   gather_tx[tid] = {count=1,gather = gather}
   local req = stun.new("request","binding",tid)
   --req.fingerprint = false
   local data = req:encode()
   local s = gather.c.socket
   s:write(data,gather.stun_ip,gather.stun_port)
   cell.timeout(time,function()
		   gather_timer(time,sid)
   end)
   cell.timeout(time,function()
		   gather_rto_timer(time,tid)
   end)
end


local function start_gather()
   local i
   local stun = stun_servers[1] -- only one stun server in this version
   for i=1 , #streams_info do
      local stream = local_streams[i]
      local que = new_que()
      stream.gather_que = que
      local locals = stream.locals
      local j
      for j=1,#locals do
	 que:append({c=locals[i],stun_ip=stun.ip,stun_port=stun.port})
      end
      cell.timeout(0,function()
		      gather_timer(ta,i)
      end)
   end
end

local gatherF = function(...)
   if states["gather"] then
	 states["gather"](...)
   end
end

local function build_pair()
   local i
   for i=1,#local_streams do
      stream = local_streams[i]
      stream.checklist_state = "CHECKLIST_RUNNING"
      stream.checklist = {}
      local l2 = {}
      deep_copy(l2,stream.locals)
      local j=1
      --remove not host candidate
      while j<=#l2 do
	 if l2[j].type ~= "CANDIDATE_TYPE_HOST" then 
	    table.remove(l2,j)
	    j = j-1
	 end
	 j = j +1 
      end
      

      for j=1,#l2 do
	 local k
	 local c1 = l2[j]
	 local remotes = remote_streams[i].locals
	 for k=1,#(remotes) do 
	    local c2 = remotes[k]
	    if c1.cid == c2.cid then
	       --todo fix peer pwd
	       peer_pwd = c2.pwd
	       local pair = {id=get_pairid(),fid=""..c1.fid..c2.fid,l=c1,r=c2,
			     state = "PAIR_FROZEN",
			     sid = c1.sid,
			     cid = c1.cid
			    }
	       table.insert(stream.checklist,pair)
	    end
	 end
      end
   end
end



local function trigger_check(sid)
   local trigger_que = local_streams[sid].trigger_que
   local trigger = trigger_que:pop()
   local sid = trigger.sid
   local pair_id = trigger.pair_id
   local tid = get_txid()
   check_tx[tid] = {count=1,sid=sid,pair_id=pair_id}
   local pair = get_pair_by_id(sid,pair_id)
   do_send_check(pair,tx_id)
   pair.state = "PAIR_IN_PROGRESS"
   return tid
   
end

local function order_check(sid)
   local stream = local_streams[sid]
   local checklist = stream.checklist
   table.sort(checklist,function(pairA,pairB)
		 local state_v ={
		    PAIR_IN_PROGRESS = 0,
		    PAIR_COMPLETED = 0,
		    PAIR_FAILED = 0,
		    PAIR_CANCELLED = 0,
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
   local pair = checklist[1]
   if pair.state == "PAIR_WAITING" or pair.state == "PAIR_FROZEN" then
      local tid = get_txid()
      check_tx[tid] = {count=1,sid=sid,pair_id=pair.id}
      assert(pair.id)
      do_send_check(pair,tid)
      pair.state = "PAIR_IN_PROGRESS"
      return tid
   end
   
end



local function check_rto_timer(time,txid)
   local tx = check_tx[txid]
   if not tx then
      return 
   end
   local count = tx.count
   local pair = get_pair_by_id(tx.sid,tx.pair_id)
   if count > 3 then
      pair.state = "PAIR_FAILED"
      update_checklist_state(tx.sid)
      --when first media failed,start other fix me
      if tx.sid == 1 then
	 if local_streams[tx.sid].checklist_state == "CHECKLIST_FAILED" then
	    local j 
	    for j=2,#local_streams do
	       start_check(j)
	    end
	 end
      end
   else      
      do_send_check(pair,txid)
      tx.count = count +1
      cell.timeout(time,function()
		      check_rto_timer(time,txid)
      end)
   end
end


local function check_timer(time,sid)
   assert(sid)
   local stream = local_streams[sid]
   local que = stream.trigger_que
   local tid 
   if que:is_que_empty() then
      tid = order_check(sid)
   else
      tid =trigger_check(sid)
   end
  cell.timeout(time,function()
		  check_timer(time,sid)
  end)

  if tid then
     cell.timeout(ta,function()
		     check_rto_timer(ta,tid)
     end)
  end
end

local function is_checklist_frozen(sid)
   local i
   for i=1,#local_streams[sid].checklist do 
      local pair = local_streams[sid].checklist[i]
      if pair.state ~= "PAIR_FROZEN" then
	 return false
      end
   end
   return true
end
local function start_check(sid)
   local stream = local_streams[sid]
   if is_checklist_frozen(sid) then 
      cell.timeout(ta,function()
		      check_timer(ta,sid)
		      end
      )
   end
end

local function form_checklist()
   build_pair()
   priority_checklist()
   sort_checklist()
   start_check(1) -- start first media
end
local function  do_ice_handshake()
   form_checklist()
end
cell.message {
   send = function(sid,cid,msg,sz)
      local validlist = local_streams[sid].validlist
      local i 
      for i=1,#validlist do
	 local pair = validlist[i]
	 if pair.cid == cid then
	    local socket = pair.l.socket
	    if opts.dtls then
	       local srtp = pair.srtp
	       local rtp,rtp_sz = lua_srtp.pack_rtp(msg,1,get_seq(),os.time())
	       local ok,new_sz = lua_srtp.protect_rtp(srtp,rtp,rtp_sz)
	       print("xxx",rtp,new_sz,rtp_sz)
	       socket:write_raw(rtp,new_sz,pair.r.addr.ip,pair.r.addr.port)
	    else
	       socket:write(msg,pair.r.addr.ip,pair.r.addr.port)
	    end
	    return 
	 end
      end
      assert(false,"should not happen,no valid pair!")
   end,
   accept_udp = function(fd,msg,sz,peer_ip,peer_port)
      --todo peek msg
      local pos,b1 = bin.unpack(">C",msg,sz)
      if b1 == 0x16 then --dtls
      elseif (state=="running" or state=="gather") and bit.rshift(b1,6) == 0x0 then
	 print(state,sz)
	 local ok,req = stun.decode(msg,sz)
	 if states[state] then
	    states[state](req,fd,peer_ip,peer_port)
	 end
      else
	 
	 local c = socket_info[fd]
	 local sid = c.sid
	 local cid = c.cid
	 local srtp
	 if opts.dtls then
	    local validlist = local_streams[sid].validlist
	    local j
	    for j=1 ,#validlist do
	       if cid == validlist[j].cid then
		  srtp = validlist[j].srtp
		  break
	       end
	    end
	    assert(srtp)
	    print(msg,sz)
	    local ok,rtp_sz = lua_srtp.unprotect_rtp(srtp,msg,sz)

	    assert(ok)
	    local new_msg,new_sz = lua_srtp.unpack_rtp(msg,rtp_sz)
	    cell.send(opts.client,"ice_receive",opts,cell.self,sid,cid,new_msg,new_sz)
	    return 
	 end
	 cell.send(opts.client,"ice_receive",opts,cell.self,sid,cid,msg,sz)
      end
   end
}


cell.command {
   start = function(...)
      role = ...
      state = "gather"
      build_host()
      start_gather()
      start_ev = cell.event()
      cell.wait(start_ev)
      return true,local_streams
   end,
   set_remotes = function(...)
      remote_streams = ...
      assert(remote_streams)
      assert(type(remote_streams) == "table")
      set_remotes_ev = cell.event()
      do_ice_handshake()
      cell.wait(set_remotes_ev)
      print("handshake completed,state:",state)
      return ok,msg
   end,
   sleep = function(T)
      cell.sleep(T)
      return true
   end
}
function cell.main(...)
   streams_info,stun_servers,opts = ...
   return true
end
