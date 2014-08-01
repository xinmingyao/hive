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
local httpd = require "http.httpd"
local sockethelper = require "http.sockethelper"
local urllib = require "http.url"
local _M = new_tab(0, 10)
_M._VERSION = '0.03'

local mt = { __index = _M }


local function response(id, ...)
	local ok, err = httpd.write_response(sockethelper.writefunc(id), ...)
	if not ok then
	   -- if err == sockethelper.socket_error , that means socket closed.
		print(string.format("fd = %d, %s", id, err))
	end
end
--writefunc, statuscode, bodyfunc, header
function mt:rep(status,headers,body)
   response(self.id,status,body,headers)
end
function _M.new(id,handle,opts)
   local code, url, method, header, body = httpd.read_request(sockethelper.readfunc(id), 8192)
   print(code,url,method)
   if code then
      if code ~= 200 then
	 response(id, code)
      else
	 local tmp = {}
	 if header.host then
	    table.insert(tmp, string.format("host: %s", header.host))
	 end
	 local path, query = urllib.parse(url)
	 table.insert(tmp, string.format("path: %s", path))
	 if query then
	    local q = urllib.parse_query(query)
	    for k, v in pairs(q) do
	       table.insert(tmp, string.format("query: %s= %s", k,v))
	    end
	 end
	 local c1,h1,b1 = handle(code, url, method, header, body)
	 --todo close socket
	 response(id,c1,b1,h1)
      end
   else
      if url == sockethelper.socket_error then
	 print("socket closed")
	-- skynet.error("socket closed")
      else
	-- skynet.error(url)
	 print("error",url)
      end
   end
      
   local t1 = setmetatable({
			      id = id
			   }, mt)
   return t1
end

return _M
