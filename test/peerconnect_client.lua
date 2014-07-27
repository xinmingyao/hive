local cell = require "cell"
local crypto = require "crypto"
local digest = crypto.digest
local hmac = crypto.hmac
local base64 = require "base64"
local ip,port = ...
local control_socket
local hanging_socket
local http = require "protocol.http"
local name = "rtc_client"
local id
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


local function keepalive(t)
   cell.timeout(t,function()
		   control_socket:write("GET /wait?peer_id="..id.." HTTP/1.0\r\n\r\n")
		   --keepalive(500)
   end)
end
local function hang_get()
   while true do
      local d1 = control_socket:readline("Content-Length:")
      local len = control_socket:readline("\r\n")
      local d2 = control_socket:readline("\r\n\r\n")
      len = tonumber(len)
      local d3 = control_socket:readbytes(len)
      print(d3)
   end
end

local hivelib = require "hive.hive_lib"
function cell.main()
   ip,port = "192.168.1.101",8888
   control_socket = cell.connect(ip,port)
   control_socket = cell.connect(ip,port)
   control_socket:write("GET /sign_in?"..name.." HTTP/1.0\r\n\r\n")
   local d1 = control_socket:readline("Content-Length:")
   local len = control_socket:readline("\r\n")
   local d2 = control_socket:readline("\r\n\r\n")
   len = tonumber(len)
   local d3 = control_socket:readbytes(len)
   local d4 = hivelib.strsplit("\r\n",d3)
   local d5 = hivelib.strsplit(",",d4[1])
   local d6 = d5[2]
   assert(d6)
   id = d6
   keepalive(0)
   return msg
end
