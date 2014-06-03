local cell = require "cell"
local peer = {}
local peer_meta  = {}
function peer_meta:offer()   
   cell.call(self.pid,start,"controlling")
end

function peer_meta:answer()
   cell.call(self.pid,start,"controlled")
end

function peer_meta:set_remotes(...)
   cell.send(self.pid,set_remotes,...)
end
function peer.new(streams_info,stun_servers,opts)
   local p = {s=streams,stun=stun_sever,opts=opts}
   if opts == nil then
      opts = {}
   end
   assert(type(opts)=="table")
   opts.client = cell.self
   local pid = cell.cmd("launch", "p2p.ice_agent_full",streams_info,stun_servers,opts)
   p.pid = pid
   return setmetatable(p,{__index = peer_meta})
end
return peer