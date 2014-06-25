--package.path = package.path .. ";./hive/?.lua;./?.lua"
--forbid global varible
--[[
mt={} 
mt.__index=function(t,k) 
   if not(mt[k]) then 
      error("attempt to read undeclared variable "..k,2) 
      return nil 
   end 
end 
mt.__newindex=function(t,k,v) 
   if not(mt[k]) then 
      error("attempt to write undeclared variable "..k,2) 
   else 
      rawset(t,k,v) 
      mt[k]=true 
   end 
end 
setmetatable(_G,mt) 
]]

local ssl = require("ssl")

local c = require "cell.c"
local csocket = require "cell.c.socket"

local msgpack = require "cell.msgpack"
local binlib = require "cell.binlib"
local t = binlib.pack("III",1,1,2)
local coroutine = coroutine
local assert = assert
local select = select
local table = table
local next = next
local pairs = pairs
local type = type

local session = 0
local port = {}
local task_coroutine = {}
local task_session = {}
local task_source = {}
local command = {}
local message = {}
local gui = {}
local cell = {}

local self = c.self
local system = c.system
local win_handle =  c.win_handle
cell.self = self
local sraw = require "cell.stable"
sraw.init()  -- init lightuserdata metatable
local event_q1 = {}
local event_q2 = {}

local watching_service = {}
local watching_session = {}

local function new_task(source, session, co, event)
	task_coroutine[event] = co
	task_session[event] = session
	task_source[event] = source
end

function cell.fork(f)
	local co = coroutine.create(function() f() return "EXIT" end)
	session = session + 1
	new_task(nil, nil, co, session)
	cell.wakeup(session)
end

function cell.timeout(ti, f)
	local co = coroutine.create(function() f() return "EXIT" end)
	session = session + 1
	c.send(system, 2, self, session, "timeout", ti)
	new_task(nil, nil, co, session)
end

function cell.sleep(ti)
	session = session + 1
	c.send(system, 2, self, session, "timeout", ti)
	coroutine.yield("WAIT", session)
end

function cell.wakeup(event)
	table.insert(event_q1, event)
end

function cell.event()
	session = session + 1
	return session
end

function cell.wait(event)
	return coroutine.yield("WAIT", event)
end

function cell.call(addr, ...)
	-- command
	session = session + 1
	local s = session
	if watching_service[addr] then
	   watching_session[s] = addr
	end
	if watching_service[addr]==false then
	   return false,"cell_exit"
	end
	local ok,err = pcall(c.send,addr, 2, cell.self, s,...)
	if not ok then
	   return false,err
	end
	return select(2,coroutine.yield("WAIT", s))
end

function cell.rawcall(addr, session, ...)
	local s = session
	if watching_service[addr] then
	   watching_session[s] = addr
	end
	if watching_service[addr]==false then
	   return false,"cell_exit"
	end
	local ok,err = pcall(c.send,addr,...)
	if not ok then
	   return false,err
	end
	return select(2,coroutine.yield("WAIT", s))
end

function cell.send(addr, ...)
	-- message
	c.send(addr, 3, ...)
end

cell.rawsend = c.send

function cell.dispatch(p)
	local id = assert(p.id)
	if p.replace then
		assert(port[id])
	else
		assert(port[id] == nil)
	end
	port[id] = p
end

function cell.cmd(...)
	return cell.call(system, ...)
end

function cell.exit()
	cell.send(system, "kill", self)
	-- no return
	cell.wait(cell.event())
end

function cell.command(cmdfuncs)
	command = cmdfuncs
end

function cell.message(msgfuncs)
	message = msgfuncs
end
function cell.add_message(k,v)
   message[k] = v
end
function cell.get_message(k)
   return message[k]
end
function cell.gui(cmdfuncs)
	gui = cmdfuncs
end
local function suspend(source, session, co, ok, op, ...)
	if ok then
		if op == "RETURN" then
		      	local ok,err = pcall(c.send,source, 1, session, true,...)
			if not ok then
			   print("cell:",cell.self," " ,err)
			end
		elseif op == "EXIT" then
			-- do nothing
		elseif op == "WAIT" then
			new_task(source, session, co, ...)
		else
			error ("Unknown op : ".. op)
		end
	elseif source then
		c.send(source, 1, session, false, op)
	else
		print(cell.self,op)
		print(debug.traceback(co))
	end
end

local function resume_co(session, ...)
	local co = task_coroutine[session]
	if co == nil then
	      	 return --flush
		--error ("Unknown response : " .. tostring(session))
	end
	local reply_session = task_session[session]
	local reply_addr = task_source[session]
	task_coroutine[session] = nil
	task_session[session] = nil
	task_source[session] = nil
	suspend(reply_addr, reply_session, co, coroutine.resume(co, ...))
end
cell.resume_co = resume_co
local function deliver_event()
	while next(event_q1) do
		event_q1, event_q2 = event_q2, event_q1
		for i = 1, #event_q2 do
			local ok, err = pcall(resume_co,event_q2[i])
			if not ok then
				print(cell.self,err)
			end
			event_q2[i] = nil
		end
	end
end

function cell.main() end

------------ sockets api ---------------
local sockets = {}
local sockets_event = {}
local sockets_arg = {}
local sockets_closed = {}
local sockets_fd = nil
local sockets_accept = {}
local sockets_udp = {}
local socket = {}
local listen_socket = {}
local socket_opts = {}
local rpc = {}
local rpc_head = {}

local socket_ssl = {}
local function close_msg(self)
	cell.send(sockets_fd, "disconnect", self.__fd)
end

local socket_meta = {
	__index = socket,
	__gc = close_msg,
	__tostring = function(self)
		return "[socket: " .. self.__fd .. "]"
	end,
}

local listen_meta = {
	__index = listen_socket,
	__gc = close_msg,
	__tostring = function(self)
		return "[socket listen: " .. self.__fd .. "]"
	end,
}



--todo:
function listen_socket:disconnect()
	sockets_accept[self.__fd] = nil
	socket.disconnect(self)
end

function cell.connect(addr, port,opts)
	sockets_fd = sockets_fd or cell.cmd("socket")
	local fd,sockfd = cell.call(sockets_fd, "connect", self, addr, port)
	assert(fd, "Connect failed")
	local obj = { __fd = fd,__sockfd = sockfd ,__opts = opts}
	socket_opts[obj.__fd] =  opts
	return setmetatable(obj, socket_meta)
end
function cell.connect_udp(...)
   sockets_fd = sockets_fd or cell.cmd("socket")
   cell.call(sockets_fd, "connect_udp", self, ...)
end
function cell.ioctl(...)
   sockets_fd = sockets_fd or cell.cmd("socket")
   cell.call(sockets_fd, "ioctl", self, ...)
end
function cell.open(port,accepter,opts)
	sockets_fd = sockets_fd or cell.cmd("socket")
	local fd,sockfd = cell.call(sockets_fd, "open", self, port)
	assert(fd, "Open failed")
	local obj = { __fd = fd,__sockfd=sockfd,__opts=opts }
	sockets_udp[obj.__fd] = accepter
	socket_opts[obj.__fd] =  opts 
	return setmetatable(obj, socket_meta)
end

function cell.listen(port, accepter,opts)
	assert(type(accepter) == "function")
	sockets_fd = sockets_fd or cell.cmd("socket")
	local fd,sockfd = cell.call(sockets_fd, "listen", self, port)
	assert(fd, "Listen failed")
	local obj = { __fd = fd,__sockfd=sockfd,__opts=opts }
	socket_opts[obj.__fd] =  opts
	sockets_accept[obj.__fd] =  function(fd, addr)
		return accepter(fd, addr, obj)
	end
	return setmetatable(obj, listen_meta)
end

function cell.bind(fd)
	sockets_fd = sockets_fd or cell.cmd("socket")
	local obj = { __fd = fd }
	return setmetatable(obj, socket_meta)
end

-- ssl start

--#define SSL_ERROR_NONE			0
--#define SSL_ERROR_SSL			1
--#define SSL_ERROR_WANT_READ		2
--#define SSL_ERROR_WANT_WRITE		3
--#define SSL_ERROR_WANT_X509_LOOKUP	4
--#define SSL_ERROR_SYSCALL		5 /* look at error stack/return value/errno */
--#define SSL_ERROR_ZERO_RETURN		6
--#define SSL_ERROR_WANT_CONNECT		7
--#define SSL_ERROR_WANT_ACCEPT		8

function socket:dtls_open(cfg)
   local fd = self.__fd
   
  -- self.__opts.ssl="dtls"
   local sockfd = self.__sockfd
   print(sockfd,cfg)
   local s,msg = ssl.wrap_nonblock(sockfd,cfg)
   if s then
      socket_ssl[fd]= {type="dtls",ssl=s,state="new",mode=cfg.mode} --sever or client
      cell.ioctl(fd,1,1) --new
      return true,s
   else
      return false,msg
   end
end

function socket:dtls_listen(cfg,ip,port)
   local fd = self.__fd
   cell.connect_udp(fd,ip,port)
   cfg.mode = "server"
   if socket.dtls_open(self,cfg) then
      local r,msg =  do_handshake(fd)
      if r then
	 cell.ioctl(fd,1,2) --completed
	 return r,msg
      else
	 return r,msg  
      end
   end
  -- return socket.dtls_open(self,cfg)
end

function socket:connect_udp(...)
   local fd = self.__fd
   cell.connect_udp(fd,...)	
end
function socket:dtls_connect(cfg,ip,port)
   local fd = self.__fd
   cell.sleep(50)
   print("xxx:",sockets_event[fd])
   cfg.mode = "client"
   cell.connect_udp(fd,ip,port)
   if socket.dtls_open(self,cfg) then
      local r,msg =  do_handshake(fd)
      if r then
	 cell.ioctl(fd,1,2) --completed
	 return r,msg
      else
	 return r,msg
      
      end
   end
end
local function handshake_wait(fd)
   assert(sockets_event[fd] == nil)
   sockets_event[fd] = cell.event()
   cell.wait(sockets_event[fd])
end

function do_handshake(fd)
   local ssl_info = socket_ssl[fd]
   assert(ssl_info,"no ssl")
   local ssl_socket = ssl_info.ssl
   print(ssl_socket)
   local err
   while true do
      err = ssl_socket:dohandshake_nonblock()
      print("handshake",err)
      if err == 0 then
      	 cell.ioctl(fd,1,2) --completed
	 return true,ssl_socket
      elseif err==2  then
	 handshake_wait(fd)
      elseif err==3  then
	 handshake_wait(fd)
      else
	 print("dtls error:",err)
	 return false,err
      end
   end
end

-- ssl end
function socket:rpc(rpc_funs)
	rpc[self.__fd] = rpc_funs
end
function socket:disconnect()
	assert(sockets_fd)
	local fd = self.__fd
	sockets[fd] = nil
	sockets_closed[fd] = true
	if sockets_event[fd] then
		cell.wakeup(sockets_event[fd])
	end

	cell.send(sockets_fd, "disconnect", fd)
end

function socket:write_raw(msg,sz,...)
   local fd = self.__fd
   cell.rawsend(sockets_fd,6,fd,sz,msg,...)
end
function socket:write(msg,...)
	local fd = self.__fd
	local sz,msg=csocket.sendpack(msg)
	cell.rawsend(sockets_fd, 6, fd,sz,msg,...)
end

local function socket_wait(fd, sep)
	assert(sockets_event[fd] == nil)
	sockets_event[fd] = cell.event()
	sockets_arg[fd] = sep
	cell.wait(sockets_event[fd])
end

function socket:readbytes(bytes)
	local fd = self.__fd
	if sockets_closed[fd] then
		sockets[fd] = nil
		return
	end
	if sockets[fd] then
		local data = csocket.pop(sockets[fd], bytes)
		if data then
			return data
		end
	end
	socket_wait(fd, bytes)
	if sockets_closed[fd] then
		sockets[fd] = nil
		return
	end
	return csocket.pop(sockets[fd], bytes)
end

function socket:readline(sep)
        local fd = self.__fd
	if sockets_closed[fd] then
		sockets[fd] = nil
		return
	end
	sep = sep or "\n"
	if sockets[fd] then
		local line = csocket.readline(sockets[fd], sep)
		if line then
			return line
		end
	end
	socket_wait(fd, sep)
	if sockets_closed[fd] then
		sockets[fd] = nil
		return
	end
	return csocket.readline(sockets[fd], sep)
end

----------------------------------------

cell.dispatch {
	id = 7,	-- gui
	dispatch = function(msg,len)
		local pos,rep = binlib.unpack("A"..len,msg,len)
        local info = msgpack:unpack(rep)
        local f = gui[info[2]]
		if f == nil then
			c.post_message(tonumber(info[1]),info[2],{-1,"Unknown gui command " ..  info[2]})
		else
			local co = coroutine.create(function()
                        local t = f(info)
                        --c.post_message(tonumber(info[1]),info[2],t)
                        return "EXIT", t end)
			suspend(source, session, co, coroutine.resume(co,info))
		end
	end
}

cell.dispatch {
	id = 6, -- socket
	dispatch = function(fd, sz, msg,...)
		local accepter = sockets_accept[fd]
		if accepter then
			-- accepter: new fd (sz) ,  ip addr (msg)
			local co = coroutine.create(function()
				local forward = accepter(sz,msg) or self
				cell.call(sockets_fd, "forward", sz , forward)
				return "EXIT"
			end)
			suspend(nil, nil, co, coroutine.resume(co))
			return
		end
		local udp = sockets_udp[fd]
		if udp then
		   local ssl_s = socket_ssl[fd]
		   if sz < 0 then --ssl event
		      assert(ssl_s,"must for ssl")		      
		  --    if ssl_s.mode == "server" and ssl_s.state == "new" then
		--	 ssl_s.state ="handshake"
		--	 local co = coroutine.create(function()
		--	        do_handshake(fd)			 
		--		return "EXIT"
		    --  	end)
		  --    	suspend(nil, nil, co, coroutine.resume(co))
			
		--	 return
		     -- else
			 if sockets_event[fd] then
			    print("handshake event:",sockets_event[fd])
			    local ev = sockets_event[fd]
			    sockets_event[fd] = nil		
			    cell.wakeup(ev)
			    return
			  else
			    print("no co")
			  end
		     -- end
		   end
		   if ssl_s and ssl_s.state == "completed" then
		      if ssl_s.cipher_type == "srtp" then
			 print("-----------",msg)
			 -- msg,sz = srtp.decode(msg,sz)
		      else
			 assert(nil,"not support")
		      end
		   end
		   if socket_opts[fd] and socket_opts[fd].protocol == "text" then
		      local co = coroutine.create(function()
						     local buffer,bsz = csocket.push(sockets[fd],msg,sz)
						     sockets[fd] = buffer
						     udp()
						     return "EXIT"
		      end)
		      suspend(nil, nil, co, coroutine.resume(co))
		      return
		   else
		      local peer_ip,peer_port = ...
		      local co = coroutine.create(function()
						     cell.send(udp,"accept_udp",fd,msg,sz,peer_ip,peer_port)
						     return "EXIT"
		      end)
		      suspend(nil, nil, co, coroutine.resume(co))
		      return
		   end
		   return 
		end
		local ev = sockets_event[fd]
		sockets_event[fd] = nil
		if sz == 0 then
			sockets_closed[fd] = true
			if ev then
				cell.wakeup(ev)
			end
		else
			local buffer, bsz = csocket.push(sockets[fd], msg, sz)
			sockets[fd] = buffer
			if ev then
				local arg = sockets_arg[fd]
				if type(arg) == "string" then
					local line = csocket.readline(buffer, arg, true)
					if line then
						cell.wakeup(ev)
					end
				else
					if bsz >= arg then
						cell.wakeup(ev)
					end
				end
			elseif rpc[fd]  then
				
				if rpc_head[fd] == nil then
					if bsz >=4 then
					
						local head = csocket.pop(sockets[fd], 4)
						local pos,len=binlib.unpack(">I",head)  
						local data = csocket.pop(sockets[fd],len)
						if data then
							rpc_head[fd]  = nil
							local pos,rep = binlib.unpack("A"..len,data)
							local info = msgpack:unpack(rep)
							local fs = rpc[fd]
							local f = fs[info[1]]
							if f then
								f(fd,info)
							else
								error ("UnSupport rpc cmd : " .. info[1])
							end
						else
						    rpc_head[fd]  = len
						end
					end
				else
					local data = csocket.pop(sockets[fd],rpc_head[fd] )
					if data then
						rpc_head[fd]  = nil
						local pos,rep = binlib.unpack("A"..rpc_head[fd],data)
						local info = msgpack:unpack(rep)
						local fs = rpc[fd]
						local f = fs[info[1]]
						print(f)
						if f then
							f(fd,info)
						else
							error ("UnSupport rpc cmd : " .. info[1])
						end
					end
				end
			else
			 -- donothing
			end
		end
	end
}

cell.dispatch {
	id = 5, -- exit
	dispatch = function()
	end
}

cell.dispatch {
	id = 4, -- launch
	dispatch = function(source, session, report, ...)
		local op = report and "RETURN" or "EXIT"
		local co = coroutine.create(function(...) return op, cell.main(...) end)
		suspend(source, session, co, coroutine.resume(co,...))
	end
}

cell.dispatch {
	id = 3, -- message
	dispatch = function(cmd, ...)
		local f = message[cmd]
		if f == nil then
			print("Unknown message ", cmd)
		else
			local co = coroutine.create(function(...) return "EXIT", f(...) end)
			suspend(nil,nil, co, coroutine.resume(co,...))
		end
	end
}

cell.dispatch {
	id = 2,	-- command
	dispatch = function(source, session, cmd, ...)
		local f = command[cmd]
		if f == nil then
			c.send(source, 1, session, false, "Unknown command " ..  cmd)
		else
			local co = coroutine.create(function(...) return "RETURN", f(...) end)
			suspend(source, session, co, coroutine.resume(co, ...))
		end
	end
}

cell.dispatch {
	id = 1,	-- response
	dispatch = function (session, ...)
		resume_co(session,...)
	end,
}

cell.dispatch {
	id = 8,	-- monitor
	dispatch = function (service)
	watching_service[service] = false
	for session, srv in pairs(watching_session) do
	    if srv == service then
	        local co = task_coroutine[session]
		if co then
		   coroutine.resume(co,false,false,"cell_exit")
		   watching_session[session] = nil
		end
	    end
	end		
	end,
}

c.dispatch(function(p,...)
	local pp = port[p]
	if pp == nil then
		deliver_event()
		error ("Unknown port : ".. p)
	end
	pp.dispatch(...)
	deliver_event()
end)

function cell.register_monitor()
      c.register_monitor(self)
end

function cell.monitor(service)
      if not watching_service[service] then
      	 watching_service[service] = true
	 local mon = c.monitor_cell()
	 if mon then
      	    cell.call(mon,"monitor",self,service)
	 else
	    print("no monitor serivce!")
	 end
      end
end

function cell.write_fd(fd,msg,...)
   local sz,msg=csocket.sendpack(msg)
   cell.rawsend(sockets_fd, 6, fd,sz,msg,...)
end
function cell.init()
   sockets_fd = sockets_fd or cell.cmd("socket")
end

function cell.push(fd,msg,sz)
   local buffer,bsz = csocket.push(sockets[fd],msg,sz)
   sockets[fd] = buffer
end
return cell
