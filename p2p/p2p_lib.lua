local bit = require "bit32"
local hivelib = require "hive.hive_lib"
local p2p_lib = {}
local lpeg = require "lpeg"
p2p_lib.stun_cookie = 0x0001
p2p_lib.ice_cookie = 0x0002
local R, S, V, P = lpeg.R, lpeg.S, lpeg.V, lpeg.P
local C, Ct, Cmt, Cg, Cb, Cc = lpeg.C, lpeg.Ct, lpeg.Cmt, lpeg.Cg, lpeg.Cb, lpeg.Cc
local Cf = lpeg.Cf
local l = {}
lpeg.locale(l)

function p2p_lib.fromdword( ip )
   assert(type(ip)=="number")
   local n4 = bit.band(bit.rshift(ip, 0),  0x000000FF)
   local n3 = bit.band(bit.rshift(ip, 8),  0x000000FF)
   local n2 = bit.band(bit.rshift(ip, 16), 0x000000FF)
   local n1 = bit.band(bit.rshift(ip, 24), 0x000000FF)

   return string.format("%d.%d.%d.%d", n1, n2, n3, n4)
end
function p2p_lib.string2ip(ip)
   assert(type(ip)=="string")
   local tip = Ct(C(l.digit^1) * "." *  C(l.digit^1) * "." * C(l.digit^0) * "." * C(l.digit^1))
   local t = tip:match(ip)
   assert(t)
   local n4 = tonumber(t[4])
   local n3 = bit.lshift(tonumber(t[3]),8)
   local n2 = bit.lshift(tonumber(t[2]),16)
   local n1 = bit.lshift(tonumber(t[1]),24)
   
   return bit.bor(n1,n2,n3,n4)
end

local function test1()
   str = "192.169.12.2"
   local ip = p2p_lib.string2ip(str)
   assert(str == p2p_lib.fromdword(ip))
end
test1()
return p2p_lib
