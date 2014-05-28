--local bin = require "cell.binlib"
local crc32 = require('protocol.crc32')
local p2p_lib = require "p2p.p2p_lib"
local bit  = require "bit32"
local crypto = require("crypto")
local STUN_MARKER = 0
local STUN_MAGIC_COOKIE = 0x2112A442
local stun = {}

local stun_meta ={}
function stun.new()
   local s = {class = nil,
	      method = nil,
	      tx_id = nil,
	      integrity = false,
	      key = nil,
	      fingerprint = true,
	      attrs = {}
   }
   return setmetatable(s,{__index = stun_meta})
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


local function encode_attr_addr(atype,addr)
   assert(type(addr)=="table")
   local ip,port
   ip = addr.ip
   port = addr.port
   assert(type(ip)=="string")
   assert(type(port)=="number")
   local f = ">SSII"
   local value = p2p_lib.string2ip(ip)
   local len = 4 + 4 
   return  bin.pack(f,atype,len,value,port)

end   

local function encode_attr_string(atype,str)
   assert(type(str)=="string")
   local f = ">SSA"..string.len(str)
   local len = string.len(str)
   return bin.pack(f,atype,len,str)
end

local function encode_attr_int(atype,num)
   assert(type(num)=="number")
   local f = ">SSI"
   local len = 4
   return bin.pack(f.atype,len,num)
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
   ['REALM'] = function(...) return encode_attr_string(0x0014,...) end,
   ['NONCE'] = function(...) return  encode_attr_string(0x0015,...) end,
   ['XOR-RELAYED-ADDRESS'] = function(...) return encode_attr_addr(0x0016,...) end,
   ['REQUESTED-ADDRESS-TYPE'] = function(...) return  encode_attr_string(0x0017,...) end,
   ['EVEN-PORT'] = function(...) return  encode_attr_string(0x0018,...) end,-- draft-ietf-behave-turn-10
   ['REQUESTED-TRANSPORT'] = function(...) return  encode_attr_string(0x0019,...) end ,--}; % draft-ietf-behave-turn-10
   ['DONT-FRAGMENT'] = function(...) return encode_attr_string(0x001a,...) end, --}; % draft-ietf-behave-turn-10
   ['XOR-MAPPED-ADDRESS'] = function(...) return   encode_attr_addr(0x0020,...) end ,--};
   ['RESERVATION-TOKEN'] = function(...) return  encode_attr_string(0x0022,...) end ,--}; % draft-ietf-behave-turn-10
   ['PRIORITY'] = function(...) return  encode_attr_int(0x0024,...) end ,--}; % draft-ietf-mmusic-ice-19
   ['USE-CANDIDATE'] = function(...) return  encode_attr_int(0x0025,...) end,--}; % draft-ietf-mmusic-ice-19
   ['PADDING'] = function(...) return encode_attr_string(0x0026,...) end ,--}; % draft-ietf-behave-nat-behavior-discovery-03
   ['RESPONSE-PORT'] = function(...) return  encode_attr_int(0x0027,...) end ,--};
   ['XOR-REFLECTED-FROM'] = function(...) return encode_attr_addr(0x0028,...) end, --}; % draft-ietf-behave-nat-behavior-discovery-03
   ['ICMP'] = function(...) return encode_attr_string(0x0030,...) end , --}; % Moved from TURN to a future I-D
   ['X-VOVIDA-XOR-MAPPED-ADDRESS'] = function(...) return encode_attr_addr(0x8020,...) end, --}; % VOVIDA non-standart
   ['X-VOVIDA-XOR-ONLY'] = function(...) return  encode_attr_string(0x8021,...) end,--}; % VOVIDA non-standart
   ['SOFTWARE'] = function(...) return encode_attr_string(0x8022,...) end ,--}; % VOVIDA 'SERVER-NAME'
   ['ALTERNATE-SERVER'] = function(...) return encode_attr_addr(0x8023,...) end,
   ['CACHE_TIMEOUT'] = function(...) return encode_attr_string(0x8027,...) end, --}; % draft-ietf-behave-nat-behavior-discovery-03
--   ['FINGERPRINT'] = function(...) return encode_attr_string(0x8028,...) end,
   ['ICE-CONTROLLED'] = function(...) return encode_attr_int(0x8029,...) end ,--}; % draft-ietf-mmusic-ice-19
   ['ICE-CONTROLLING'] = function(...) return encode_attr_int(0x802a,...) end ,--}; % draft-ietf-mmusic-ice-19
   ['RESPONSE-ORIGIN'] = function(...) return  encode_attr_addr(0x802b,...) end,
   ['OTHER-ADDRESS'] = function(...) return encode_attr_addr(0x802c,...) end,
   ['X-VOVIDA-SECONDARY-ADDRESS'] = function(...) return encode_attr_addr(0x8050,...) end,--}; % VOVIDA non-standart
   ['CONNECTION-REQUEST-BINDING'] = function(...) return encode_attr_string(0xc001,...) end,
   ['BINDING-CHANGE'] = function(...) return encode_attr_string(0xc002,...) end
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
   [0x0020] = function(...) return 'XOR-MAPPED-ADDRESS' , decode_attr_addr(...) end ,--};
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
--   [0x8028] = function(...) return 'FINGERPRINT', decode_attr_string(...) end,
   [0x8029] = function(...) return 'ICE-CONTROLLED', decode_attr_int(...) end ,--}; % draft-ietf-mmusic-ice-19
   [0x802a] = function(...) return 'ICE-CONTROLLING', decode_attr_int(...) end ,--}; % draft-ietf-mmusic-ice-19
   [0x802b] = function(...) return 'RESPONSE-ORIGIN', decode_attr_addr(...) end,
   [0x802c] = function(...) return 'OTHER-ADDRESS', decode_attr_addr(...) end,
   [0x8050] = function(...) return 'X-VOVIDA-SECONDARY-ADDRESS', decode_attr_addr(...) end,--}; % VOVIDA non-standart
   [0xc001] = function(...) return 'CONNECTION-REQUEST-BINDING', decode_attr_string(...) end,
   [0xc002] = function(...) return 'BINDING-CHANGE', decode_attr_string(...) end
}

function stun.encode(req)
   assert(req and type(req)=="table")
   assert(type(req.tx_id) == "number")
   local attrs = req.attrs
   local k,v,data
   data = ""
   for k,v in attrs do
      if encode_attr[k] then
	 data = data .. encode_attr[k](v)
      end
   end
   local bin
   local s_type = get_type(req)
   local len = string.len(data)
   local f = ">IILA" 
   -- txid must long ,and 4 byte 0 + txid = 96 bit transactionid
   data = bin.pack(f,STUN_MAGIC_COOKIE,0,req.tx_id,data)
   if req.fingerprint then
      len = len + 8 
      f = ">SSA"..msg_len
      local size = string.len(bin) + 8 -20
      local pos,s_type,msg = bin.unpack(f,bin)
      local msg = bin.pack(">SSA",s_type,size,msg)
      local crc = bit32.bxor(crc32.hash(msg),0x5354554e)
      bin = bin.pack(">SSACCCCA",s_type,size,msg,0x80,0x28,0x0,ox4,crc)
   end
   if req.integrity and req.key then
      local msg_len = string.len(bin)-4 
      f = ">SSA"..msg_len
      local pos,s_type,t,msg = bin.unpack(f,bin)
      local size = string.len(bin) + 24 - 20
      local bin2 = bin.pack(">SSA",s_type,size,msg)
      local finger = crypto:sha_mac(req.key,bin2)
      bin = bin.pack(">SSACCCCA",s_type,len,msg,0x0,0x8,0x0,0x14,finger)
   end
   return bin
end
function stun.decode(bin,sz,key)
   local rep = stun.new()
   local size = sz - 8
   local f = "A" .. size.."CCCCA32"
   local data = bin.unpack(">A"..sz,bin,sz)
   local pos,msg,c1,c2,c3,c4,rest,crc = bin.unpack(f,data)
   --check finger print
   if c1 == 0x080 and c1 == 0x28 and c3 == 0x0 and c4 == 0x04 then
      local crc1 = bit32.bxor(crc32.hash(msg),0x5354554e)
      if crc1 ~= crc then
	 return false
      end
      f = ">SSA"..string.len(msg) -4 
      pos,s_type,len,data = bin.unpack(f,bin,sz)
      req.fingerprint = true
   else
      req.fingerprint = false
      print("no crc was found in stun message")
   end
   
   --check integrity
   if key then
      size = string.len(data) - 24
      f = ">A"..size.."CCCC".."A20"
      pos,msg,c1,c2,c3,c4,finger  = bin.unpack(f,data)
      if c1 == 0x000 and c1 == 0x08 and c3 == 0x00 and c4 == 0x14 and finger then
	 local finger2 = crypto:sha_mac(key,msg)
	 if finger == finger2 then
	    local old,payload
	    pos,s_type,old,payload = bin.unpack(">SSA"..(string.len(msg)-4),msg)
	    data = bin.pack(">SSA",s_type,old-24,payload)
	    req.integrity = true
	 else
	    return false
	 end
      else
	 req.integrity = false
      end

   end
   local  pos,s_type,length,magic_cookie,tx_id = bin.unpack(">SSIA12",data)
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
      [0x008] = "createpermission",
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
      if f ~= nil then
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