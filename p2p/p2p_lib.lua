local bit = require "bit32"
local p2p_lib = {}
p2p_lib.stun_cookie = 0x0001
p2p_lib.ice_cookie = 0x0002

function p2p_lib.fromdword( ip )
   assert(type(ip)=="number")
   local n4 = bit.band(bit.rshift(ip, 0),  0x000000FF)
   local n3 = bit.band(bit.rshift(ip, 8),  0x000000FF)
   local n2 = bit.band(bit.rshift(ip, 16), 0x000000FF)
   local n1 = bit.band(bit.rshift(ip, 24), 0x000000FF)

   return string.format("%d.%d.%d.%d", n1, n2, n3, n4)
end

return p2p_lib
