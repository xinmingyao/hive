--local bin = require "cell.binlib"
local p2p_lib = require "p2p.p2p_lib"
local bit  = require "bit32"
local STUN_MARKER = 0
local STUN_MAGIC_COOKIE = 0x2112A442
local stun = {}

local stun_meta ={}
function stun.new()
   local s = {class = nil,
		method = nil,
		transactionid = nil,
		integrity = false,
		key = nil,
		fingerprint = true,
		attrs = {}
   }
   return setmetatable(s,{__index = stun_meta})
end 

local function check_fingerprint(data)
   
end

local function  decode_attr_addr(data,sz,len,pos)
   local v = {}
   local pos1
   pos1,v.type,v.family,v.port,v.ip = bin.unpack(">CCSI",data,sz,pos)
   v.ip = p2p_lib.fromdword(v.ip)
   return pos1,v
end

local function decode_attr_int(data,sz,len,pos)
   return bin.unpack(">S",data,sz,pos)
end

local function decode_attr_string(data,sz,len,pos)
   return bin.unpack(">A"..len,data,sz,pos)
end

local function decode_attr_err(data,sz,len,pos)
   local v = {}
   local pos1 
   local t = len - 4
   pos1,v.reserve,v.class,v.number,v.reason = bin.unpack(">SCCA"..t,data,sz,pos)
   v.class = bin.xor(v.class,oxF) -- only 4 bit for class
   return pos1,v 
end


   

local encode_attr = {
   ['MAPPED-ADDRESS'] = function(...) return  encode_attr_addr(0x0001,...) end,
   ['RESPONSE-ADDRESS'] = function(...) return encode_attr_addr(0x0002,...) end,-- % Obsolete
   ['CHANGE-REQUEST'] = function(...) return encode_change_req(0x0003,...) end,
   ['SOURCE-ADDRESS'] = function(...) return  encode_attr_addr(0x0004,...) end,
   ['CHANGED-ADDRESS'] = function(...) return  encode_attr_addr(0x0005,...) end,
   ['USERNAME'] = function(...) return encode_attr_string(0x0006,...) end,
   ['PASSWORD'] = function(...) return  encode_attr_string(0x0007,...) end,
   ['MESSAGE-INTEGRITY'] = function(...) return encode_attr_string(0x0008,...) end,
   ['ERROR-CODE'] = function(...) return  decode_attr_err(0x0009,...) end,
   ['UNKNOWN-ATTRIBUTES'] = function(...) return  encode_attr_string(0x000a,...) end,
   ['REFLECTED-FROM'] = function(...) return  encode_attr_string(0x000b,...) end,
   ['CHANNEL-NUMBER'] = function(...) return encode_attr_int(0x000c,...) end,
   ['LIFETIME'] = function(...) return  encode_attr_string(0x000d,...)   end,
   ['ALTERNATE-SERVER'] = function(...) return encode_attr_addr(0x000e,...)   end,
   ['MAGIC-COOKIE'] = function(...) return  encode_attr_string(0x000f,...) end,
   ['BANDWIDTH'] = function(...) return  encode_attr_int(0x0010,...) end,
   ['DESTINATION-ADDRESS'] = function(...) return  encode_attr_addr(0x0011,...) end,
   ['XOR-PEER-ADDRESS'] = function(...) return encode_attr_xaddr(0x0012,...) end,
   ['DATA'] = function(...) return  encode_attr_string(0x0013,...) end,
   ['REALM'] = function(...) return encode_attr_string(0x0014...) end,
   ['NONCE'] = function(...) return  encode_attr_string(0x0015,...) end,
   ['XOR-RELAYED-ADDRESS'] = function(...) return encode_attr_addr(0x0016,...) end,
   [0x0017] = function(...) return 'REQUESTED-ADDRESS-TYPE', encode_attr_string(...) end,
   [0x0018] = function(...) return 'EVEN-PORT', decode_attr_string(...) end,-- draft-ietf-behave-turn-10
   [0x0019] = function(...) return 'REQUESTED-TRANSPORT', decode_attr_string(...) end ,--}; % draft-ietf-behave-turn-10
   [0x001a] = function(...) return 'DONT-FRAGMENT', decode_attr_string(...) end, --}; % draft-ietf-behave-turn-10
   [0x0020] = function(...) return 'XOR-MAPPED-ADDRESS'  decode_attr_addr(...) end ,--};
   [0x0022] = function(...) return 'RESERVATION-TOKEN', decode_attr_string(...) end ,--}; % draft-ietf-behave-turn-10
   [0x0024] = function(...) return 'PRIORITY', decode_attr_int(...) end ,--}; % draft-ietf-mmusic-ice-19
   [0x0025] = function(...) return 'USE-CANDIDATE', decode_attr_int(...) end,--}; % draft-ietf-mmusic-ice-19
   [0x0026] = function(...) return 'PADDING', decode_attr_string(...) end ,--}; % draft-ietf-behave-nat-behavior-discovery-03
   [0x0027] = function(...) return 'RESPONSE-PORT', decode_attr_int(...) end ,--};
   [0x0028] = function(...) return 'XOR-REFLECTED-FROM', decode_attr_addr(...) end, --}; % draft-ietf-behave-nat-behavior-discovery-03
   [0x0030] = function(...) return 'ICMP', decode_attr_string(...) end , --}; % Moved from TURN to a future I-D
   [0x8020] = function(...) return 'X-VOVIDA-XOR-MAPPED-ADDRESS', decode_attr_addr(...) end, --}; % VOVIDA non-standart
   [0x8021] = function(...) return 'X-VOVIDA-XOR-ONLY', decode_attr_string(...) end,--}; % VOVIDA non-standart
   [0x8022] = function(...) return 'SOFTWARE', decode_attr_string(...) end ,--}; % VOVIDA 'SERVER-NAME'
   [0x8023] = function(...) return 'ALTERNATE-SERVER', decode_attr_addr(...) end,
   [0x8027] = function(...) return 'CACHE_TIMEOUT', decode_attr_string(...) end, --}; % draft-ietf-behave-nat-behavior-discovery-03
   [0x8028] = function(...) return 'FINGERPRINT', decode_attr_string(...) end,
   [0x8029] = function(...) return 'ICE-CONTROLLED', decode_attr_int(...) end ,--}; % draft-ietf-mmusic-ice-19
   [0x802a] = function(...) return 'ICE-CONTROLLING', decode_attr_int(...) end ,--}; % draft-ietf-mmusic-ice-19
   [0x802b] = function(...) return 'RESPONSE-ORIGIN', decode_attr_addr(...) end,
   [0x802c] = function(...) return 'OTHER-ADDRESS', decode_attr_addr(...) end,
   [0x8050] = function(...) return 'X-VOVIDA-SECONDARY-ADDRESS', decode_attr_addr(...) end,--}; % VOVIDA non-standart
   [0xc001] = function(...) return 'CONNECTION-REQUEST-BINDING', decode_attr_string(...) end,
   [0xc002] = function(...) return 'BINDING-CHANGE', decode_attr_string(...) end
}

local decode_attr = {
   [0x0001] = function(...) return 'MAPPED-ADDRESS', decode_attr_addr(...) end,
   [0x0002] = function(...) return 'RESPONSE-ADDRESS', decode_attr_addr(...) end,-- % Obsolete
   [0x0003] = function(...) return 'CHANGE-REQUEST', decode_change_req(...) end,
   [0x0004] = function(...) return 'SOURCE-ADDRESS', decode_attr_addr(...) end,
   [0x0005] = function(...) return 'CHANGED-ADDRESS', decode_attr_addr(...) end,
   [0x0006] = function(...) return 'USERNAME', decode_attr_string(...) end,
   [0x0007] = function(...) return 'PASSWORD', decode_attr_string(...) end,
   [0x0008] = function(...) return 'MESSAGE-INTEGRITY',decode_attr_string(...) end,
   [0x0009] = function(...) return 'ERROR-CODE', decode_attr_err(...) end,
   [0x000a] = function(...) return 'UNKNOWN-ATTRIBUTES', decode_attr_string(...) end,
   [0x000b] = function(...) return 'REFLECTED-FROM', decode_attr_string(...) end,
   [0x000c] = function(...) return 'CHANNEL-NUMBER', decode_attr_int(...) end,
   [0x000d] = function(...) return 'LIFETIME', decode_attr_string(...)   end,
   [0x000e] = function(...) return 'ALTERNATE-SERVER', decode_attr_addr(...)   end,
   [0x000f] = function(...) return 'MAGIC-COOKIE', decode_attr_string(...) end,
   [0x0010] = function(...) return 'BANDWIDTH', decode_attr_int(...) end,
   [0x0011] = function(...) return 'DESTINATION-ADDRESS', decode_attr_addr(...) end,
   [0x0012] = function(...) return 'XOR-PEER-ADDRESS', decode_attr_xaddr(..., TID) end,
   [0x0013] = function(...) return 'DATA', decode_attr_string(...) end,
   [0x0014] = function(...) return 'REALM', decode_attr_string(...) end,
   [0x0015] = function(...) return 'NONCE', decode_attr_string(...) end,
   [0x0016] = function(...) return 'XOR-RELAYED-ADDRESS', decode_attr_xaddr(..., TID) end,
   [0x0017] = function(...) return 'REQUESTED-ADDRESS-TYPE', decode_attr_string(...) end,
   [0x0018] = function(...) return 'EVEN-PORT', decode_attr_string(...) end,-- draft-ietf-behave-turn-10
   [0x0019] = function(...) return 'REQUESTED-TRANSPORT', decode_attr_string(...) end ,--}; % draft-ietf-behave-turn-10
   [0x001a] = function(...) return 'DONT-FRAGMENT', decode_attr_string(...) end, --}; % draft-ietf-behave-turn-10
   [0x0020] = function(...) return 'XOR-MAPPED-ADDRESS'  decode_attr_addr(...) end ,--};
   [0x0022] = function(...) return 'RESERVATION-TOKEN', decode_attr_string(...) end ,--}; % draft-ietf-behave-turn-10
   [0x0024] = function(...) return 'PRIORITY', decode_attr_int(...) end ,--}; % draft-ietf-mmusic-ice-19
   [0x0025] = function(...) return 'USE-CANDIDATE', decode_attr_int(...) end,--}; % draft-ietf-mmusic-ice-19
   [0x0026] = function(...) return 'PADDING', decode_attr_string(...) end ,--}; % draft-ietf-behave-nat-behavior-discovery-03
   [0x0027] = function(...) return 'RESPONSE-PORT', decode_attr_int(...) end ,--};
   [0x0028] = function(...) return 'XOR-REFLECTED-FROM', decode_attr_addr(...) end, --}; % draft-ietf-behave-nat-behavior-discovery-03
   [0x0030] = function(...) return 'ICMP', decode_attr_string(...) end , --}; % Moved from TURN to a future I-D
   [0x8020] = function(...) return 'X-VOVIDA-XOR-MAPPED-ADDRESS', decode_attr_addr(...) end, --}; % VOVIDA non-standart
   [0x8021] = function(...) return 'X-VOVIDA-XOR-ONLY', decode_attr_string(...) end,--}; % VOVIDA non-standart
   [0x8022] = function(...) return 'SOFTWARE', decode_attr_string(...) end ,--}; % VOVIDA 'SERVER-NAME'
   [0x8023] = function(...) return 'ALTERNATE-SERVER', decode_attr_addr(...) end,
   [0x8027] = function(...) return 'CACHE_TIMEOUT', decode_attr_string(...) end, --}; % draft-ietf-behave-nat-behavior-discovery-03
   [0x8028] = function(...) return 'FINGERPRINT', decode_attr_string(...) end,
   [0x8029] = function(...) return 'ICE-CONTROLLED', decode_attr_int(...) end ,--}; % draft-ietf-mmusic-ice-19
   [0x802a] = function(...) return 'ICE-CONTROLLING', decode_attr_int(...) end ,--}; % draft-ietf-mmusic-ice-19
   [0x802b] = function(...) return 'RESPONSE-ORIGIN', decode_attr_addr(...) end,
   [0x802c] = function(...) return 'OTHER-ADDRESS', decode_attr_addr(...) end,
   [0x8050] = function(...) return 'X-VOVIDA-SECONDARY-ADDRESS', decode_attr_addr(...) end,--}; % VOVIDA non-standart
   [0xc001] = function(...) return 'CONNECTION-REQUEST-BINDING', decode_attr_string(...) end,
   [0xc002] = function(...) return 'BINDING-CHANGE', decode_attr_string(...) end
}

function stun.decode(bin,sz)
   local rep = stun.new()
   local  pos,s_type,length,magic_cookie,tx_id = bin.unpack(">SSIA12",data,sz)
   --libnice stunmessage 
   local s_type1 = s_type
   local b1 =  bit.brshift(2,bit.band(s_type1,0x3e00))  
   local b2 =  bit.brshift(1,bit.band(s_type1,0x00e0))  
   local b3 = bit.band(s_type,0x000f)
   local method = bit.bor(b1,b2,b3)
   --hack google/msn data
   if s_type == 0x0115 then
      s_type =0x0017
   end
   local b4 = bit.brshift(7,bit.band(s_type,0x0100))
   local b5 = bit.brshift(4,bit.band(s_type,0x0010))
   local class = bit.bor(b4,b5)
   
   local method2str = {
      [0x001] = "binding",
      [0x002] = "shared_secret",
      [0x003] = "allocate",
      [0x004] = "refresh",
      [0x005] = "connect",
      [0x006] = "send",
      [0x007] = "data",
      [0x008] = "createpermission"
      [0x009] = "channelbind"
   }
   rep.method =  method2str[method]
   local class2str = {
      [0] = "request",
      [1] = "indication",
      [2] = "response",
      [3] = "error"
   }
   rep.class = class2str[class]
   while( pos < sz ) do
      local t,len,tt
      pos, t,len= bin.unpack(">SS", data,sz,pos)      
      local f = decode_attr[t]
      if f != nil then
	 pos,key,value = f(data,len,pos)
	 rep[key] = value
      else
	 pos,tt = bin.unpack(">A"..len,data,sz,pos)
	 rep[t] = tt
	 print("warning unknow type:",t)
      end
   end
      return rep
end

function stun.stun_test1()

end

return stun