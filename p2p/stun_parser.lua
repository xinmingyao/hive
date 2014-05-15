local bin = require "cell.binlib"
local p2p_lib = require "p2p.p2p_lib"
local stun = {}
local stun_cookie = 0x0001
local ice_cookie = 0x0002
stun.attr = 
{
  -- Mandatory attributes */
  -- 0x0000 */        -- reserved */
  STUN_ATTRIBUTE_MAPPED_ADDRESS=0x0001,    -- RFC5389 */
  STUN_ATTRIBUTE_RESPONSE_ADDRESS=0x0002,  -- old RFC3489 */
  STUN_ATTRIBUTE_CHANGE_REQUEST=0x0003,    -- old RFC3489 */
  STUN_ATTRIBUTE_SOURCE_ADDRESS=0x0004,    -- old RFC3489 */
  STUN_ATTRIBUTE_CHANGED_ADDRESS=0x0005,  -- old RFC3489 */
  STUN_ATTRIBUTE_USERNAME=0x0006,      -- RFC5389 */
  STUN_ATTRIBUTE_PASSWORD=0x0007,    -- old RFC3489 */
  STUN_ATTRIBUTE_MESSAGE_INTEGRITY=0x0008,    -- RFC5389 */
  STUN_ATTRIBUTE_ERROR_CODE=0x0009,      -- RFC5389 */
  STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES=0x000A,    -- RFC5389 */
  STUN_ATTRIBUTE_REFLECTED_FROM=0x000B,    -- old RFC3489 */
  STUN_ATTRIBUTE_CHANNEL_NUMBER=0x000C,        -- TURN-12 */
  STUN_ATTRIBUTE_LIFETIME=0x000D,      -- TURN-12 */
  -- MS_ALTERNATE_SERVER is only used by Microsoft's dialect, probably should
  -- * not to be placed in STUN_ALL_KNOWN_ATTRIBUTES */
  STUN_ATTRIBUTE_MS_ALTERNATE_SERVER=0x000E, -- MS-TURN */
  STUN_ATTRIBUTE_MAGIC_COOKIE=0x000F,        -- midcom-TURN 08 */
  STUN_ATTRIBUTE_BANDWIDTH=0x0010,      -- TURN-04 */
  STUN_ATTRIBUTE_DESTINATION_ADDRESS=0x0011,        -- midcom-TURN 08 */
  STUN_ATTRIBUTE_REMOTE_ADDRESS=0x0012,    -- TURN-04 */
  STUN_ATTRIBUTE_PEER_ADDRESS=0x0012,    -- TURN-09 */
  STUN_ATTRIBUTE_XOR_PEER_ADDRESS=0x0012,    -- TURN-12 */
  STUN_ATTRIBUTE_DATA=0x0013,      -- TURN-12 */
  STUN_ATTRIBUTE_REALM=0x0014,      -- RFC5389 */
  STUN_ATTRIBUTE_NONCE=0x0015,      -- RFC5389 */
  STUN_ATTRIBUTE_RELAY_ADDRESS=0x0016,    -- TURN-04 */
  STUN_ATTRIBUTE_RELAYED_ADDRESS=0x0016,    -- TURN-09 */
  STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS=0x0016,    -- TURN-12 */
  STUN_ATTRIBUTE_REQUESTED_ADDRESS_TYPE=0x0017,  -- TURN-IPv6-05 */
  STUN_ATTRIBUTE_REQUESTED_PORT_PROPS=0x0018,  -- TURN-04 */
  STUN_ATTRIBUTE_REQUESTED_PROPS=0x0018,  -- TURN-09 */
  STUN_ATTRIBUTE_EVEN_PORT=0x0018,  -- TURN-12 */
  STUN_ATTRIBUTE_REQUESTED_TRANSPORT=0x0019,  -- TURN-12 */
  STUN_ATTRIBUTE_DONT_FRAGMENT=0x001A,  -- TURN-12 */
  -- 0x001B */        -- reserved */
  -- 0x001C */        -- reserved */
  -- 0x001D */        -- reserved */
  -- 0x001E */        -- reserved */
  -- 0x001F */        -- reserved */
  STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS=0x0020,    -- RFC5389 */
  STUN_ATTRIBUTE_TIMER_VAL=0x0021,      -- TURN-04 */
  STUN_ATTRIBUTE_REQUESTED_IP=0x0022,    -- TURN-04 */
  STUN_ATTRIBUTE_RESERVATION_TOKEN=0x0022,    -- TURN-09 */
  STUN_ATTRIBUTE_CONNECT_STAT=0x0023,    -- TURN-04 */
  STUN_ATTRIBUTE_PRIORITY=0x0024,      -- ICE-19 */
  STUN_ATTRIBUTE_USE_CANDIDATE=0x0025,    -- ICE-19 */
  -- 0x0026 */        -- reserved */
  -- 0x0027 */        -- reserved */
  -- 0x0028 */        -- reserved */
  -- 0x0029 */        -- reserved */
  -- 0x002A-0x7fff */      -- reserved */

  -- Optional attributes */
  -- 0x8000-0x8021 */      -- reserved */
  STUN_ATTRIBUTE_OPTIONS=0x8001, -- libjingle */
  STUN_ATTRIBUTE_MS_VERSION=0x8008,    -- MS-TURN */
  STUN_ATTRIBUTE_SOFTWARE=0x8022,      -- RFC5389 */
  STUN_ATTRIBUTE_ALTERNATE_SERVER=0x8023,    -- RFC5389 */
  -- 0x8024 */        -- reserved */
  -- 0x8025 */        -- reserved */
  -- 0x8026 */        -- reserved */
  -- 0x8027 */        -- reserved */
  STUN_ATTRIBUTE_FINGERPRINT=0x8028,    -- RFC5389 */
  STUN_ATTRIBUTE_ICE_CONTROLLED=0x8029,    -- ICE-19 */
  STUN_ATTRIBUTE_ICE_CONTROLLING=0x802A,    -- ICE-19 */
  -- 0x802B-0x804F */      -- reserved */
  STUN_ATTRIBUTE_MS_SEQUENCE_NUMBER=0x8050,     -- MS-TURN */
  -- 0x8051-0x8053 */      -- reserved */
  STUN_ATTRIBUTE_CANDIDATE_IDENTIFIER=0x8054    -- MS-ICE2 */
  -- 0x8055-0xFFFF */      -- reserved */
} 

stun.method = {
  STUN_BINDING=0x001,    -- RFC5389 */
  STUN_SHARED_SECRET=0x002,  -- old RFC3489 */
  STUN_ALLOCATE=0x003,    -- TURN-12 */
  STUN_SET_ACTIVE_DST=0x004,  -- TURN-04 */
  STUN_REFRESH=0x004,  -- TURN-12 */
  STUN_SEND=0x004,  -- TURN-00 */
  STUN_CONNECT=0x005,    -- TURN-04 */
  STUN_OLD_SET_ACTIVE_DST=0x006,  -- TURN-00 */
  STUN_IND_SEND=0x006,    -- TURN-12 */
  STUN_IND_DATA=0x007,    -- TURN-12 */
  STUN_IND_CONNECT_STATUS=0x008,  -- TURN-04 */
  STUN_CREATEPERMISSION= 0x008, -- TURN-12 */
  STUN_CHANNELBIND= 0x009 -- TURN-12 */
} 

stun.class = {
  STUN_REQUEST=0,
  STUN_INDICATION=1,
  STUN_RESPONSE=2,
  STUN_ERROR=3
} 

stun.error = 
{
  STUN_ERROR_TRY_ALTERNATE=300,      -- RFC5389 */
  STUN_ERROR_BAD_REQUEST=400,      -- RFC5389 */
  STUN_ERROR_UNAUTHORIZED=401,      -- RFC5389 */
  STUN_ERROR_UNKNOWN_ATTRIBUTE=420,    -- RFC5389 */
  STUN_ERROR_ALLOCATION_MISMATCH=437,   -- TURN-12 */
  STUN_ERROR_STALE_NONCE=438,      -- RFC5389 */
  STUN_ERROR_ACT_DST_ALREADY=439,    -- TURN-04 */
  STUN_ERROR_UNSUPPORTED_FAMILY=440,      -- TURN-IPv6-05 */
  STUN_ERROR_WRONG_CREDENTIALS=441,    -- TURN-12 */
  STUN_ERROR_UNSUPPORTED_TRANSPORT=442,    -- TURN-12 */
  STUN_ERROR_INVALID_IP=443,      -- TURN-04 */
  STUN_ERROR_INVALID_PORT=444,      -- TURN-04 */
  STUN_ERROR_OP_TCP_ONLY=445,      -- TURN-04 */
  STUN_ERROR_CONN_ALREADY=446,      -- TURN-04 */
  STUN_ERROR_ALLOCATION_QUOTA_REACHED=486,    -- TURN-12 */
  STUN_ERROR_ROLE_CONFLICT=487,      -- ICE-19 */
  STUN_ERROR_SERVER_ERROR=500,      -- RFC5389 */
  STUN_ERROR_SERVER_CAPACITY=507,    -- TURN-04 */
  STUN_ERROR_INSUFFICIENT_CAPACITY=508,    -- TURN-12 */
  STUN_ERROR_MAX=699
} 
stun.msg_return = {
  STUN_MESSAGE_RETURN_SUCCESS = 0 ,
  STUN_MESSAGE_RETURN_NOT_FOUND = 1,
  STUN_MESSAGE_RETURN_INVALID = 2,
  STUN_MESSAGE_RETURN_NOT_ENOUGH_SPACE = 3,
  STUN_MESSAGE_RETURN_UNSUPPORTED_ADDRESS = 4
} 

local req_meta = {}
function stun.new_stun_req(tx,a)
   local attrs = a or {}
   local req = {tx = tx ,attrs = attrs,cookie = stun_cookie}
   return setmetatable(req,{__index = req_meta})
end

function stun.new_ice_req(tx,a)
   local attrs = a or {}
   local req = {tx = tx ,attrs = attrs,cookie = ice_cookie}
   return setmetatable(req,{__index = req_meta})
end

local function append_attr(req,attr_type,len,value)
   local attrs = req.attrs
   attrs[#attrs+1] = {type = attr_type,length = len,value = value} 
end


function req_meta:append_change_ipport()
   append_attr(self,stun.attr.STUN_ATTRIBUTE_CHANGE_REQUEST,4,0x0006)
end
function req_meta:append_change_port()
   append_attr(self,stun.attr.STUN_ATTRIBUTE_CHANGE_REQUEST,4,0x0002)
end
function req_meta:append_controlling(tie)
   append_attr(self,stun.attr.STUN_ATTRIBUTE_ICE_CONTROLLING,8,tie)
end
function req_meta:append_controlled(tie)
   append_attr(self,stun.attr.STUN_ATTRIBUTE_ICE_CONTROLLED,8,tie)
end
function req_meta:append_use_candi()
   append_attr(self,stun.attr.STUN_ATTRIBUTE_USE_CANDIDATE,0)
end
function req_meta:append_user(user)
   append_attr(self,stun.attr.STUN_ATTRIBUTE_USERNAME,#user,user)
end
function req_meta:append_pwd(pwd)
   append_attr(self,stun.attr.STUN_ATTRIBUTE_USERNAME,#pwd,pwd)
end

function req_meta:append_foundation(found)
   append_attr(self,stun.attr.STUN_ATTRIBUTE_CANDIDATE_IDENTIFIER,#found,found)
end
function req_meta:append_priority(prior)
   append_attr(self,stun.attr.STUN_ATTRIBUTE_PRIORITY,4,prior)
end

function req_meta:append_attr(attr_type,len,value)
   local attrs = self.attrs
   attrs[#attrs+1] = {type = attr_type,len = len,value = value} 
end

function req_meta:build_bin()
   local tx,attrs,cookie,magic
   tx = self.tx
   attrs = self.attrs
   cookie = self.cookie
   magic = self.magic or 0x123

   assert(tx and type(tx) == "number")
   local data = ""
   if attrs then
      local k,v
      for k,v in pairs(attrs) do
	 if v.length == 4 then
	    assert(type(v.value) == "number")
	    local f = ">SSI"
	    data = data .. bin.pack(f,v.type,v.length,v.value)
	 elseif v.length == 8 then
	    assert(type(v.value) == "number")
	    local f = ">SSL"
	    data = data .. bin.pack(f,v.type,v.length,v.value)
	 elseif v.length == 0 then
	    local f = ">SS"
	    data = data .. bin.pack(f,v.type,v.length)
	 else
	    assert(type(v.value) == "string")
	    assert(v.length == #v.value)
	    local f = ">SSA"
	    data = data .. bin.pack(f,v.type,v.length,v.value)
	    --print("not suppport!!!!!")
	    --return false,string.format("not support attr:%d %d %d",v.type,v.length,v.value)
	 end
      end
   end
   local txid = bin.pack(">IL",cookie,tx) --12 byte txid 4:type,8:ident
   local len = #data
   local req 

   if len > 0 then
      local f = ">SSIAA" 
      req = bin.pack(f,stun.method.STUN_BINDING,len,magic,txid,data)
   else
      local f = ">SSIA" 

      req = bin.pack(f,stun.method.STUN_BINDING,len,magic,txid)
   end
   return true,req
end

stun.paser_rep = function(data,sz)
   local rep ={}
   local pos
   assert(sz >=20)
   pos,rep.type,rep.length,rep.magic,rep.cookie,rep.tx = bin.unpack(">SSIIL",data,sz)
   while( pos < sz ) do
      local t,len
      pos, t,len= bin.unpack(">SS", data,sz,pos)      
      local tt,family,port,ip
      if t == stun.attr.STUN_ATTRIBUTE_MAPPED_ADDRESS then
	 pos,tt, family,port,ip = bin.unpack(">CCSI",data,sz,pos)
	 rep.external_ip = p2p_lib.fromdword(ip) 
	 rep.external_port = port
	 rep.external_family = family
      elseif t == stun.attr.STUN_ATTRIBUTE_CHANGED_ADDRESS then
	 pos,tt, family,port,ip = bin.unpack(">CCSI",data,sz,pos)
	 rep.changed_ip = p2p_lib.fromdword(ip) 
	 rep.changed_port = port
	 rep.changed_family = family
      elseif t == stun.attr.STUN_ATTRIBUTE_SOURCE_ADDRESS then
	 pos,tt, family,port,ip = bin.unpack(">CCSI",data,sz,pos)
	 rep.source_ip = p2p_lib.fromdword(ip) 
	 rep.source_port = port
	 rep.source_family = family
      else
	 pos,tt = bin.unpack(">A"..len,data,sz,pos)
	 --tofo fix flush
      end
   end 
   return true,rep
end

return stun

