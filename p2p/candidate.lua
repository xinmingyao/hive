local bit = "bit32"
local candidate = {}
local candi_meta = {}
local PREF_HOST = 120
local PREF_PEER_SERVER_REFLEXIVE = 110
local PREF_SERVER_REFLEXIVE = 100  
local PREF_RELAYED = 60
function candi_meta:get()
end

--ICE 4.1.2.1 "RECOMMENT FORMULA" ID-19 
function candidate.ice_priority_full(type_pref,local_pref,component_id)
   assert(type_pref and local_pref and component_id)
   return 0x1000000 * type_pref + 0x100 * local_pref + 0x100 - component_id
end
--ICE 5.7.2 
local function calc_pairs_priority(l_p,r_p)
   local max,min,t
   if l_p > r_p then
      max = l_p
      t = 1 
   else
      max = r_p
      t = 0
   end
   if l_p < r_p then
      min = l_p
   else
      min = r_p
   end
  
   return bit.lshift(1,32) * min + 2 * max + t
end

function candidate.new()
   local candi = {}
   return setmetatable(candi,{__index = candi_meta})
end

return candidate