-- Copyright (C) Yichun Zhang (agentzh)
local cell = require "cell"
local bit = require "bit32"
local wbproto = require "protocol.ws_proto"
local new_tab = wbproto.new_tab
local _recv_frame = wbproto.recv_frame
local _send_frame = wbproto.send_frame
local http_ver = 1.1 --ngx.req.http_version
local str_lower = string.lower
local char = string.char
local str_find = string.find
local crypto = require "crypto"
local digest = crypto.digest
local hmac = crypto.hmac
local base64 = require "base64"
local band = bit.band
local rshift = bit.rshift
local type = type
local setmetatable = setmetatable
-- local print = print


local _M = new_tab(0, 10)
_M._VERSION = '0.03'

local mt = { __index = _M }


function _M.new(fd,handle,opts)
   local sock = cell.bind(fd)
   --   cell.listen(ip_port,accepter)
   local str = sock:readline("\r\n\r\n")
   local req  = wbproto.parse(str)
   local headers = req.headers
   local val = headers.Upgrade

   if type(val) == "table" then
      val = val[1]
   end
   if not val or str_lower(val) ~= "websocket" then
      return nil, "bad \"upgrade\" request header"
   end
   print(str)   
   local key = headers["Sec-WebSocket-Key"]
   if type(key) == "table" then
      key = key[1]
   end
   if not key then
      return nil, "bad \"sec-websock-key\" request header"
   end

   local ver = headers["Sec-WebSocket-Version"]
   if type(ver) == "table" then
      ver = ver[1]
   end
   if not ver or ver ~= "13" then
      return nil, "bad \"sec-websock-version\" request header"
   end

   local protocols = headers["Sec-WebSocket-Protocol"]
   if type(protocols) == "table" then
      protocols = protocols[1]
   end

   local ngx_header = {}
   if protocols then
      ngx_header["Sec-WebSocket-Protocol"] = protocols
   end
   ngx_header["connection"] = "Upgrade"
   ngx_header["upgrade"] = "websocket"
   
   local d = digest.new("sha1")
-- local sha1 = d:final(key .. "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
   local sha1 = crypto.digest("sha1",key.."258EAFA5-E914-47DA-95CA-C5AB0DC85B11",true)
   ngx_header["sec-websocket-accept"] = base64.encode(sha1)
   
--   ngx_header["Content-Type"] = nil

   local status = 101
   local request_line = "HTTP/1.1 ".. status .." Switching Protocols"
   local rep ={}
   table.insert(rep,request_line)
   local k,v
   for k,v in pairs(ngx_header) do
      local str = string.format('%s: %s',k,v)
      table.insert(rep,str)
   end
   rep = table.concat(rep,"\r\n")
   rep = rep.."\r\n\r\n"
   print(rep)
   sock:write(rep)
   
   local max_payload_len, send_masked, timeout
   if opts then
      max_payload_len = opts.max_payload_len
      send_masked = opts.send_masked
      timeout = opts.timeout	
      if timeout then
	 sock:settimeout(timeout)
      end
   end

   
   
   local t1 = setmetatable({
			  sock = sock,
			  max_payload_len = max_payload_len or 65535,
			  send_masked = send_masked,
		       }, mt)

   cell.dispatch {
      id = 6, -- socket
      replace = true,
      dispatch = function(fd,sz, msg,...)
	 cell.push(fd,msg,sz)
	 local co = coroutine.create(function()
					--print(t1:recv_frame())
					local data ,typ,err = t1:recv_frame()
					handle[typ](data)
	 end)
	 coroutine.resume(co)
      end
   }
   return t1
end


function _M.set_timeout(self, time)
    local sock = self.sock
    if not sock then
        return nil, nil, "not initialized yet"
    end

    return sock:settimeout(time)
end


function _M.recv_frame(self)

    local sock = self.sock
    if not sock then
        return nil, nil, "not initialized yet"
    end
    local data, typ, err =  _recv_frame(sock, self.max_payload_len, true)
    if not data and not str_find(err, ": timeout", 1, true) then
        self.fatal = true
    end
    return data, typ, err
end


local function send_frame(self, fin, opcode, payload)
    if self.fatal then
        return nil, "fatal error already happened"
    end

    local sock = self.sock
    if not sock then
        return nil, "not initialized yet"
    end
    
    local bytes, err = _send_frame(sock, fin, opcode, payload,
                                   self.max_payload_len, self.send_masked)
    return bytes, err
end
_M.send_frame = send_frame


function _M.send_text(self, data)
    return send_frame(self, true, 0x1, data)
end


function _M.send_binary(self, data)
    return send_frame(self, true, 0x2, data)
end


function _M.send_close(self, code, msg)
    local payload
    if code then
        if type(code) ~= "number" or code > 0x7fff then
        end
        payload = char(band(rshift(code, 8), 0xff), band(code, 0xff))
                        .. (msg or "")
    end
    return send_frame(self, true, 0x8, payload)
end


function _M.send_ping(self, data)
    return send_frame(self, true, 0x9, data)
end


function _M.send_pong(self, data)
    return send_frame(self, true, 0xa, data)
end


return _M
