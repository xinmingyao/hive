local cell = require "cell"
local bit = require "bit32"
local math = require "math"
local srtp = require "lua_srtp"
local sdp = require "protocol.sdp"
local peer = {}
local peer_meta  = {}

function peer_meta:offer()   
   return cell.call(self.pid,"start","controlling")
end

function peer_meta:answer(remote_info)
   return cell.call(self.pid,"start","controlled")
end

function peer_meta:set_remotes(RemoteSdp,Candis)
   local sdp_info = sdp.parse(RemoteSdp)
   if not sdp_info then
      return false,"sdp not ok"
   end
   local audio_ssrc = sdp_info:ssrc("audio")
   local video_ssrc = sdp_info:ssrc("video")
   --local candis = sdp_info:candis("audio")
   local is_bundle = sdp_info:is_bundle()
   local is_rtcp_mux = sdp_info:is_rtcp_mux()
   
   local ok,local_streams = cell.call(self.pid,"start","controlling")
   if not ok then
      return false ,"start error"
   end
   local ok,r = cell.call(self.pid,"set_remotes_candis",Candis)
   if ok then
      local local_sdp = {}
      self.local_sdp = local_sdp
      local_sdp.audio_ssrc = audio_ssrc
      local_sdp.video_ssrc = video_ssrc
      local_sdp.is_bundle = is_bundle
      local_sdp.is_rtcp_mux = is_rtcp_mux
      local info = {}
      table.insert(info,"v=0")
      table.insert(info,"o=test 931665148 2 IN IP4 192.0.0.1")
      table.insert(info,"s=-")
      table.insert(info,"t=0 0")
      return true
   else
      return false
   end
end

function peer_meta:get_local_sdp()
   return self.sdp_info
end
function peer_meta:send(sid,cid,msg,sz)
   local pid = self.pid
   if self.dtls then
      local r = self.rtp
      local ts = os.time()
      msg,sz = srtp.pack_rtp(msg,sz,self.ssrc,ts,self.seq)
      self.seq = self.seq + 1
   end
   cell.send(self.pid,"send",sid,cid,msg,sz)
end

local function ice_receive(opts,agent,sid,cid,msg,sz)
   local ssrc,ts,seq
   if opts.dtls then
      --msg,sz,ssrc,ts,seq = srtp.unpack(msg,sz)
   end
   local f =  cell.get_message("receive")
   assert(f)
   f(sid,cid,msg,sz)
end

function peer.new(...)
   local audio_enabled,video_enabled,stun_servers,opts = ...
   local audio,video = true,true
   local seq_num_fir = 0
   local audio_ssrc = 44444
   local video_ssrc = 55543
   local global_state ="initial"
   if opts == nil then
      opts = {}
   end
   local user = "user"
   local pwd = "pwd"
   local ip = "192.168.203.157"
   local bundle = true
   local rtcp_mux = true
   -- only support bundle
   local streams_info =
      {
	 {sid=1,
	  components = {
	     {
		cid=1,user=user,pwd=pwd,port=port,ip=ip
	     }
	  }
	 }
      }
   assert(type(opts)=="table")
   local cfg = {
      protocol = "dtlsv1",
      key = "./certs/server/key.pem",
      certificate = "./certs/server/cert.pem",
      cafile = "./certs/server/cacerts.pem",
      verify = {"peer", "fail_if_no_peer_cert"},
      options = {"all", "no_sslv2"}
   }
   if opts.cfg == nil then
      opts.cfg = cfg
   end
   opts.client = cell.self
   if opts.dtls == true then
      local ssrc
      if not opts.ssrc then
	 ssrc = math.random(1,bit.lshift(1,20))
      end
      p.seq = 1
      p.ssrc = ssrc
   end
   cell.add_message("ice_receive",ice_receive)
   local p = {s=streams,stun=stun_sever,opts=opts}
   local pid = cell.cmd("launch", "p2p.ice_agent_full",streams_info,stun_servers,opts)
   p.pid = pid
   return setmetatable(p,{__index = peer_meta})
end
return peer

