local cell = require "cell"
local users = {}
local meeting_no
local sdp = require "protocol.sdp"
local stun_servers =
   {
      {ip="107.23.150.92",port=3478}
   }
cell.command {
   join_meeting= function(user,gate)
      print(user,gate)
      local list = {}
      for k,v in pairs(users) do
	 cell.send(v.gate,"join_meeting",user)
	 table.insert(list,k)
      end
      users[user] = {gate=gate}
      if #list then
	 cell.send(gate,"list_user",list)
      end
      return true
   end,
   offer = function(user,data)
      assert(users[user],"user must exist!")
      local peer_sdp = sdp.parse(data.sdp)
      local peer_candis = data.candidates
      assert(peer_sdp and peer_candis)
      local webrtc_client = rtc.new(true,true,stun_servers)
      webrtc_client:answer(peer_sdp,peer_candis)
      local local_sdp,audio_candis,vedio_candis=webrtc_client:get_local_sdp()
      local rep
      local tmp1 = {}
      local i
      for i in ipairs(audio_candis) do
	 local js = {sdpMLineIndex=0,
		     sdpMid= "audio",
		     candidate = audio_candis[i].."\r\n"}
	 table.insert(tmp1,js)
      end
      for i in ipairs(vedio_candis) do
	 local js = {sdpMLineIndex=1,
		     sdpMid= "video",
		     candidate = vedio_candis[i].."\r\n"}
	 table.insert(tmp1,js)
      end
      local_stream = {}
      local audio_ssrc = sdp_info:ssrc("audio")
      local video_ssrc = sdp_info:ssrc("video")
      local_stream.audio_ssrc = audio_ssrc
      local_stream.video_ssrc = video_ssrc
      users[user].local_stream = local_stream
      return local_sdp,tmp1
   end
}

cell.message {
   chat = function(from,data)
      for k,v in pairs(users) do
	 if k ~= from then
	    cell.send(v.gate,"chat",from,data)
	 end
      end
   end
}

function cell.main(...)
   meeting_no = ...
   print("start meetint:",meeting_no)
end
