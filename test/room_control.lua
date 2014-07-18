local cell = require "cell"
local ws_server = require "protocol.ws_server"
local socket
local server  
local json = require "cjson"
local webrtc
local rtc = require "p2p.webrtc_connection"
local peer_sdp 
local peer_candis ={}
local sdp = require "protocol.sdp"
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

local  handle = {
   text = function(msg)
      print("receive:",msg)
      local m = json.decode(msg)
      local cmd = m.type
      if cmd == "offer" then
	 local sdp1 = sdp.parse(m.sdp)
	 --print(sdp1:ssrc("audio"))
	 print(sdp1:is_bundle())
	 peer_sdp = sdp1
      elseif cmd == "add_candidate" then
	 local t1 = m.candidate
	 if t1:find("udp") then
	    table.insert(peer_candis,m)
	 end
      elseif cmd == "start" then
	 print("start-----")
	 print(webrtc:answer(peer_sdp,peer_candis))
	 local local_sdp,audio_candis,vedio_candis=webrtc:get_local_sdp()
	 local rep
	 local tmp1 = {}
	 local i
	 for i in ipairs(audio_candis) do
	    local js = {SdpMLineIndex=0,
			sdpMid= "audio",
			candidate = audio_candis[i].."\r\n"}
	    --js = json.encode(js)
	    table.insert(tmp1,js)
	 end

	 for i in ipairs(vedio_candis) do
	    local js = {SdpMLineIndex=1,
			sdpMid= "vedio",
			candidate = audio_candis[i].."\r\n"}
	    --js = json.encode(js)
	    table.insert(tmp1,js)
	 end
	 
	 rep = {
	    type="answer",
	    sdp = local_sdp,
	    candidates = tmp1}
	 rep = json.encode(rep)
	 server:send_text(
	    rep
	 )
      else
	 print("not support cmd:",cmd)
      end
   end  
}
function cell.main(fd)
   cell.timeout(0,function()
		   server,err = ws_server.new(fd,handle)
		   if server then
		      return true
		   else
		      print("error",err)
		      return false
		   end
   end)
   cell.timeout(0,function()
		   local stun_servers =
		      {
			 {ip="107.23.150.92",port=3478}
		      }
		   webrtc = rtc.new(true,true,stun_servers)
   end)
end
