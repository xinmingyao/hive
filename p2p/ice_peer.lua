local cell = require "cell"
local bit = require "bit32"
local math = require "math"
local srtp = require "lua_srtp"
local peer = {}
local peer_meta  = {}

function peer_meta:offer()   
   return cell.call(self.pid,"start","controlling")
end

function peer_meta:answer(remote_info)
   return cell.call(self.pid,"start","controlled")
end

function peer_meta:set_remotes(...)
   cell.call(self.pid,"set_remotes",...)
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
      msg,sz,ssrc,ts,seq = srtp.unpack(msg,sz)
   end
   local f =  cell.get_message("receive")
   assert(f)
   f(sid,cid,msg,sz)
end

function peer.new(streams_info,stun_servers,opts)
   local p = {s=streams,stun=stun_sever,opts=opts}
   if opts == nil then
      opts = {}
   end
   assert(type(opts)=="table")
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
   local pid = cell.cmd("launch", "p2p.ice_agent_full",streams_info,stun_servers,opts)
   p.pid = pid
   return setmetatable(p,{__index = peer_meta})
end
return peer

