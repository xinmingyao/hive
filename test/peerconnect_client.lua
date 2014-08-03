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
local peers = {}
local hivelib = require "hive.hive_lib"
local cjson = require "cjson"
local rtc = require "p2p.webrtc_connection"
local peer_sdp 
local peer_candis ={}
local local_candis = {}
local sdp = require "protocol.sdp"
local m_socket
local webrtc_client
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


local function send_peer(peer_id,rep)
   m_socket = cell.connect(ip,port)
   m_socket:write("POST /message?peer_id="..id.."&to="..peer_id .." HTTP/1.0\r\n"
		     .. "Content-Length: "..string.len(rep) .."\r\n"
		     .. "Content-Type: text/plain\r\n"
		     .."\r\n"
		     ..rep		     
   )
   m_socket:disconnect()
end
local function answer_to()
   print("start-----")
   print(webrtc_client:answer(peer_sdp,peer_candis))
   local local_sdp,audio_candis,vedio_candis=webrtc_client:get_local_sdp()
   local rep
   local tmp1 = {}
   local i
   for i in ipairs(audio_candis) do
      local js = {sdpMLineIndex=0,
		  sdpMid= "audio",
		  candidate = audio_candis[i].."\r\n"}
      --js = json.encode(js)
      table.insert(tmp1,js)
   end
   
   for i in ipairs(vedio_candis) do
      local js = {sdpMLineIndex=1,
		  sdpMid= "video",
		  candidate = vedio_candis[i].."\r\n"}
      --js = json.encode(js)
      table.insert(tmp1,js)
   end
   
   rep = {
      type="answer",
      sdp = local_sdp,
      --candidates = tmp1
   }
   rep = cjson.encode(rep)
   -- print(rep)
   send_peer(peer_id,rep)
   local i,v
   for i,v in ipairs(tmp1) do
      send_peer(peer_id,cjson.encode(v))
   end
end

local function  handle_peer_message(peer_id,data)
   local msg = cjson.decode(data)
   assert(msg)
   --print(msg)
   cmd = msg.type
   --for k,v in pairs(msg) do
     -- print(k,v)
   --end
   if msg.type == "offer" then
      local sdp1 = sdp.parse(msg.sdp)
      print(sdp1:is_bundle())
      peer_sdp = sdp1
      cell.timeout(1200,function()
		      answer_to()
      end)
   elseif msg.candidate ~= nil  then
      local t1 = msg.candidate
      if t1:find("udp") then
	 table.insert(peer_candis,msg)
      end
   elseif cmd == "start" then
      
   else
      print("not support cmd:",cmd)
   end   
end

local function keepalive(t)
   cell.timeout(t,function()
		   hanging_socket = cell.connect(ip,port)
		   hanging_socket:write("GET /wait?peer_id="..id.." HTTP/1.0\r\n\r\n")
		   --keepalive(500)HTTP/1.0\r\n\r\n
		  local d1 = hanging_socket:readline("Content-Length:")
		 
		  local len = hanging_socket:readline("\r\n")
		  local d2 = hanging_socket:readline("\r\n\r\n")
		  len = tonumber(len)
		 
		  local d3 = hanging_socket:readbytes(len)
		  --print(d1)
		  --print(d2)
		  d2 = d1 ..d2
		  local p1 = d2:find("Pragma:")
		  local p2 = d2:find("\r\n",p1)
		  local p3 = d2:sub(p1+8,p2)
		  print(p3)
		  print(d3)
		  peer_id = tonumber(p3)
		  if peer_id ~= id and d3:find("{") then 
		     handle_peer_message(peer_id,d3)
		  else
		     local d4 = hivelib.strsplit("\r\n",d3)
		     local d5 = hivelib.strsplit(",",d4[1])
		     local d6 = d5[2]
		     d6 = tonumber(d6)
		     peers[d6] = d5
		  end
		  hanging_socket:disconnect()
		  keepalive(0) 
   end)
end



function cell.main()
   ip,port = "192.168.1.101",8888
   print(ip,port)
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
   print("my id",id)
   keepalive(0)
   cell.timeout(0,function()
		   local stun_servers =
		      {
			 {ip="107.23.150.92",port=3478}
		      }
		   webrtc_client = rtc.new(true,true,stun_servers)
   end)
   return msg
end
