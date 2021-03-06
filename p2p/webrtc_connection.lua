local cell = require "cell"
local bit = require "bit32"
local math = require "math"
local srtp = require "lua_srtp"
local sdp = require "protocol.sdp"

local peer_meta = {}
local peer = {}
local local_streams = {}
local remote_streams = {}
--stream {type=audio unicast=recvonly  ssrc=1 msid=2 label=3 mslabel=4 cname=5}
function peer_meta:add_stream(stream)
   table.insert(local_streams,stream)
end

function peer_meta:get_stream_by_id(id)
   local i,s
   for i,s in ipairs(local_streams) do
      if s.msid == id then
	 return s
      end
   end

   for i,s in ipairs(remote_streams) do
      if s.msid == id then
	 return s
      end
   end
   return nil
end

function peer_meta:offer()   
   local streams_info =
      {
	 {sid=1,
	  components = {
	     {
		cid=1,user=self.opts.user,pwd=self.opts.pwd,port=self.opts.port,ip=self.opts.ip
	     }
	  }
	 }
      }
   local ok,local_streams =  cell.call(self.pid,"start","controlling")
   self.local_sdp_info.candidates = local_streams[1].locals
end


function peer_meta:answer(sdp_info,CandisStr)

   --local file = io.open("./test/1.sdp","w")
   --file:write(RemoteSdp)
--   local sdp_info = sdp.parse(RemoteSdp)
   assert(sdp_info)
   local audio_ssrc = sdp_info:ssrc("audio")
   local video_ssrc = sdp_info:ssrc("video")
   --local candis = sdp_info:candis("audio")
   local is_bundle = sdp_info:is_bundle()
   local is_rtcp_mux = sdp_info:is_rtcp_mux()   
   self.local_sdp_info.is_bundle = is_bundle
   self.is_rtcp_mux = is_rtcp_mux
   
   local streams_info =
      {
	 {sid=1,
	  components = {
	     {
		cid=1,user=self.opts.user,pwd=self.opts.pwd,port=self.opts.port,ip=self.opts.ip
	     }
	  }
	 }
      }
   local ok,local_streams = cell.call(self.pid,"start","controlled",streams_info)
   if not ok then
      return false ,"start error"
   end
   self.local_sdp_info.candidates = local_streams[1].locals
   self.remote_sdp = sdp_info
   local user,pwd
   local ice_info = sdp_info:ice_info()
   user = ice_info.user
   pwd = ice_info.pwd
   local ok,audio,video = sdp.get_remotes(CandisStr,user,pwd,is_rtcp_mux)
   
   assert(ok)
   local remote_stream= {sid=1}
   remote_stream.locals = audio
   for k,v in pairs(audio) do
      for k1,v1 in pairs(v) do
	 --print(k1,v1)
      end
   end
   cell.timeout(0,function()
		   cell.call(self.pid,"set_remotes",{remote_stream})
   end)
   
end

function peer_meta:get_local_sdp()
   local finger = self.opts.fingerprint
   local t = {}
   local len = finger:len()
   local i=1
   while i<len do
      table.insert(t,finger:sub(i,i+1))
      i = i + 2
   end
   local fstr = table.concat(t,":")
   return self.local_sdp_info:get_sdp(fstr)
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
   print("=========",f)
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
   local user = "jT8RGVnRypR+NSQe"
   local pwd = "PAiyzxXhGeYvKUPLXPLryQfg"
   local ip = "192.168.1.102"
   
   
   assert(type(opts)=="table")
   if opts.user == nil then
      opts.user = user
   end
   
   if opts.pwd == nil then
      opts.pwd = pwd --todo fix random_key
   end
   
   if opts.ip == nil then
      opts.ip = ip
   end
   if opts.port == nil then
      opts.port = 7000 --todo fix get from port_manager
   end
   local cfg = {
      protocol = "dtlsv1",
      key = "./certs/ss/key.key",
      password= "12345678",
      certificate = "./certs/ss/cert.pem",
      cafile = "./certs/ss/ca.crt",
      verify = {"none"},
      depth = 2,
      options = {"all", "no_sslv2"}
   }
   if opts.dtls_cfg == nil then
      opts.dtls=true
      opts.dtls_config = cfg
   end
   print("xxxxxxxxxxxx",cfg.certificate)
   opts.client = cell.self
   local x509 = require "ssl.x509"
   local f = io.open(cfg.certificate)
   local str = f:read("*a")
   f:close()
   local cert = x509.load(str)
   assert(cert,"get cert error")
   opts.fingerprint = cert:digest("sha256")
   if opts.dtls == true then
      local ssrc
      if not opts.ssrc then
	 ssrc = math.random(1,bit.lshift(1,20))
      end
   end
   cell.add_message("ice_receive",ice_receive)
   local local_sdp_info = sdp.new_sdp_info()
   local p = {s=streams,stun=stun_sever,opts=opts,local_sdp_info=local_sdp_info}
   p.seq = 1
   p.ssrc = ssrc
   local pid = cell.cmd("launch", "p2p.ice_agent_full",streams_info,stun_servers,opts)
   p.pid = pid
   --print("monitor",cell.monitor(pid))
   return setmetatable(p,{__index = peer_meta})
end
return peer

