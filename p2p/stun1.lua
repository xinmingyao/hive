local bin = require "cell.binlib"
local crc32 = require "protocol.crc32"
local p2p_lib = require "p2p.p2p_lib"
local bit  = require "bit32"
local crypto = require "crypto"
local hmac = crypto.hmac
local STUN_MARKER = 0
local STUN_MAGIC_COOKIE = 0x2112A442
local stun = {}

local stun_meta ={}
function stun.new(c,m,t,a)
   if a == nil then
      a = {}
   end
   assert(type(a)=="table")
   local s = {class = c,
	      method = m,
	      tx_id = t,
	      integrity = false,
	      key = nil,
	      fingerprint = true,
	      attrs = a
   }
   return setmetatable(s,{__index = stun_meta})
end 

function stun_meta:add_attr(k,v)
   self.attrs[k] = v
end

function stun_meta:get_addr_value(k)
   return self.attrs[k]
end

local function  decode_attr_xaddr(data,len,sz,pos)
   assert(len==8)
   local v = {}
   local pos1
   pos1,v.type,v.family,v.port,v.ip = bin.unpack(">CCSI",data,sz,pos)
   assert(v.family == 1)
   v.port = bit.bxor(v.port,bit.rshift(STUN_MAGIC_COOKIE,16))
   v.ip = bit.bxor(v.ip,STUN_MAGIC_COOKIE)
   v.ip = p2p_lib.fromdword(v.ip)
   return pos1,v
end

local function  decode_attr_addr(data,len,sz,pos)
   assert(len==8)
   local v = {}
   local pos1
   pos1,v.type,v.family,v.port,v.ip = bin.unpack(">CCSI",data,sz,pos)
   v.ip = p2p_lib.fromdword(v.ip)
   return pos1,v
end

local function decode_attr_int(data,len,sz,pos)
   assert(len==4 or len == 8)
   if len == 4 then
      return bin.unpack(">I",data,sz,pos)
   else
      return bin.unpack(">L",data,sz,pos)
   end
end

local function decode_attr_string(data,len,sz,pos)
   return bin.unpack(">A"..len,data,sz,pos)
end

local function decode_attr_err(data,len,sz,pos)
   local v = {}
   local pos1 
   local t = len - 4
   pos1,v.reserve,v.class,v.number,v.reason = bin.unpack(">SCCA"..t,data,sz,pos)
   v.class = bin.xor(v.class,oxF) -- only 4 bit for class
   return pos1,v 
end
local function encode_attr_err(atype,err)
   assert(type(err) == "table")
   return bin.pack(">SCCA",err.reserve,err.class,err.number,err.reason)
end

local function encode_attr_addr(atype,addr)
   assert(type(addr)=="table")
   local ip,port
   ip = addr.ip
   port = addr.port
   assert(type(ip)=="string")
   assert(type(port)=="number")
   local ip_int = p2p_lib.string2ip(ip)
   local len = 4 + 4 
   return  bin.pack(">SSII",atype,len,ip_int,port)

end   


local function encode_attr_xaddr(atype,addr)
   assert(type(addr)=="table")
   local ip,port
   ip = addr.ip
   port = addr.port
   assert(type(ip)=="string")
   assert(type(port)=="number")
   port = bit.bxor(port,bit.rshift(STUN_MAGIC_COOKIE,16))
   local ip_int = p2p_lib.string2ip(ip)
   ip_int = bit.bxor(ip_int,STUN_MAGIC_COOKIE)
   local len = 4 + 4 
   return  bin.pack(">SSCCSI",atype,len,0,1,port,ip_int)

end   


local function encode_attr_string(atype,str)
   assert(type(str)=="string")
   local len = string.len(str)
   local f = ">SSA"
   return bin.pack(f,atype,len,str)
end

local function encode_attr_int(atype,num)
   assert(type(num)=="number")
   local f = ">SSI"
   local len = 4
   return bin.pack(f,atype,len,num)
end

local function encode_attr_long(atype,num)
   assert(type(num)=="number")
   local f = ">SSL"
   local len = 8
   return bin.pack(f.atype,len,num)
end

local f = {
   MAPPED_ADDRESS = function(...) 
      return 	 encode_attr_addr(0x0001) 
   end,
   AA = function(...) 
     return  print(...)
   end,
}
local encode_attr = {
   MAPPED_ADDRESS = function(...) return  encode_attr_addr(0x0001,...) end,
   RESPONSE_ADDRESS = function(...) return encode_attr_addr(0x0002,...) end,-- % Obsolete
   CHANGE_REQUEST = function(...) return encode_change_req(0x0003,...) end,
   SOURCE_ADDRESS = function(...) return  encode_attr_addr(0x0004,...) end,
   CHANGED_ADDRESS = function(...) return  encode_attr_addr(0x0005,...) end,
   USERNAME = function(...) return encode_attr_string(0x0006,...) end,
   PASSWORD = function(...) return  encode_attr_string(0x0007,...) end,
   MESSAGE_INTEGRITY = function(...) return encode_attr_string(0x0008,...) end,
   ERROR_CODE = function(...) return  encode_attr_err(0x0009,...) end,
   UNKNOWN_ATTRIBUTES = function(...) return  encode_attr_string(0x000a,...) end,
   REFLECTED_FROM = function(...) return  encode_attr_string(0x000b,...) end,
   CHANNEL_NUMBER = function(...) return encode_attr_int(0x000c,...) end,
   LIFETIME = function(...) return  encode_attr_string(0x000d,...)   end,
   ALTERNATE_SERVER = function(...) return encode_attr_addr(0x000e,...)   end,
   MAGIC_COOKIE = function(...) return  encode_attr_string(0x000f,...) end,
   BANDWIDTH = function(...) return  encode_attr_int(0x0010,...) end,
   DESTINATION_ADDRESS = function(...) return  encode_attr_addr(0x0011,...) end,
   XOR_PEER_ADDRESS = function(...) return encode_attr_xaddr(0x0012,...) end,
   DATA = function(...) return  encode_attr_string(0x0013,...) end,
   REALM = function(...) return encode_attr_string(0x0014,...) end,
   NONCE = function(...) return  encode_attr_string(0x0015,...) end,
   XOR_RELAYED_ADDRESS = function(...) return encode_attr_addr(0x0016,...) end,
   REQUESTED_ADDRESS_TYPE = function(...) return  encode_attr_string(0x0017,...) end,
   EVEN_PORT = function(...) return  encode_attr_string(0x0018,...) end,-- draft-ietf-behave-turn-10
   REQUESTED_TRANSPORT = function(...) return  encode_attr_string(0x0019,...) end ,--}; % draft-ietf-behave-turn-10
   DONT_FRAGMENT = function(...) return encode_attr_string(0x001a,...) end, --}; % draft-ietf-behave-turn-10
   XOR_MAPPED_ADDRESS = function(...) return   encode_attr_xaddr(0x0020,...) end ,--};
   RESERVATION_TOKEN = function(...) return  encode_attr_string(0x0022,...) end ,--}; % draft-ietf-behave-turn-10
   PRIORITY = function(...) return  encode_attr_int(0x0024,...) end ,--}; % draft-ietf-mmusic-ice-19
   USE_CANDIDATE = function(...) return  encode_attr_int(0x0025,...) end,--}; % draft-ietf-mmusic-ice-19
   PADDING = function(...) return encode_attr_string(0x0026,...) end ,--}; % draft-ietf-behave-nat-behavior-discovery-03
   RESPONSE_PORT = function(...) return  encode_attr_int(0x0027,...) end ,--};
   XOR_REFLECTED_FROM = function(...) return encode_attr_addr(0x0028,...) end, --}; % draft-ietf-behave-nat-behavior-discovery-03
   ICMP = function(...) return encode_attr_string(0x0030,...) end , --}; % Moved from TURN to a future I-D
   X_VOVIDA_XOR_MAPPED_ADDRESS = function(...) return encode_attr_addr(0x8020,...) end, --}; % VOVIDA non-standart
   X_VOVIDA_XOR_ONLY = function(...) return  encode_attr_string(0x8021,...) end,--}; % VOVIDA non-standart
   SOFTWARE = function(...) return encode_attr_string(0x8022,...) end ,--}; % VOVIDA 'SERVER-NAME'
   ALTERNATE_SERVER = function(...) return encode_attr_addr(0x8023,...) end,
   CACHE_TIMEOUT = function(...) return encode_attr_string(0x8027,...) end, --}; % draft-ietf-behave-nat-behavior-discovery-03
--   FINGERPRINT = function(...) return encode_attr_string(0x8028,...) end,
   ICE_CONTROLLED = function(...) return encode_attr_int(0x8029,...) end ,--}; % draft-ietf-mmusic-ice-19
   ICE_CONTROLLING = function(...) return encode_attr_int(0x802a,...) end ,--}; % draft-ietf-mmusic-ice-19
   RESPONSE_ORIGIN = function(...) return  encode_attr_addr(0x802b,...) end,
   OTHER_ADDRESS = function(...) return encode_attr_addr(0x802c,...) end,
   X_VOVIDA_SECONDARY_ADDRESS = function(...) return encode_attr_addr(0x8050,...) end,--}; % VOVIDA non-standart
   CONNECTION_REQUEST_BINDING = function(...) return encode_attr_string(0xc001,...) end,
   BINDING_CHANGE = function(...) return encode_attr_string(0xc002,...) end
}

local decode_attr = {}
decode_attr[0x0001] = function(...) return 'MAPPED_ADDRESS', decode_attr_addr(...) end
decode_attr[0x0002] = function(...) return 'RESPONSE_ADDRESS', decode_attr_addr(...) end-- % Obsolete
decode_attr[0x0003] = function(...) return 'CHANGE_REQUEST', decode_change_req(...) end
decode_attr[0x0004] = function(...) return 'SOURCE_ADDRESS', decode_attr_addr(...) end
decode_attr[0x0005] = function(...) return 'CHANGED_ADDRESS', decode_attr_addr(...) end
decode_attr[0x0006] = function(...) return 'USERNAME', decode_attr_string(...) end
decode_attr[0x0007] = function(...) return 'PASSWORD', decode_attr_string(...) end
decode_attr[0x0008] = function(...) return 'MESSAGE_INTEGRITY',decode_attr_string(...) end
decode_attr[0x0009] = function(...) return 'ERROR_CODE', decode_attr_err(...) end
decode_attr[0x000a] = function(...) return 'UNKNOWN_ATTRIBUTES', decode_attr_string(...) end
decode_attr[0x000b] = function(...) return 'REFLECTED_FROM', decode_attr_string(...) end
decode_attr[0x000c] = function(...) return 'CHANNEL_NUMBER', decode_attr_int(...) end
decode_attr[0x000d] = function(...) return 'LIFETIME', decode_attr_string(...)   end
decode_attr[0x000e] = function(...) return 'ALTERNATE_SERVER', decode_attr_addr(...)   end
decode_attr[0x000f] = function(...) return 'MAGIC_COOKIE', decode_attr_string(...) end
decode_attr[0x0010] = function(...) return 'BANDWIDTH', decode_attr_int(...) end
decode_attr[0x0011] = function(...) return 'DESTINATION_ADDRESS', decode_attr_addr(...) end
decode_attr[0x0012] = function(...) return 'XOR_PEER_ADDRESS', decode_attr_xaddr(..., TID) end
decode_attr[0x0013] = function(...) return 'DATA', decode_attr_string(...) end
decode_attr[0x0014] = function(...) return 'REALM', decode_attr_string(...) end
decode_attr[0x0015] = function(...) return 'NONCE', decode_attr_string(...) end
decode_attr[0x0016] = function(...) return 'XOR_RELAYED_ADDRESS', decode_attr_xaddr(..., TID) end
decode_attr[0x0017] = function(...) return 'REQUESTED_ADDRESS_TYPE', decode_attr_string(...) end
decode_attr[0x0018] = function(...) return 'EVEN_PORT', decode_attr_string(...) end-- draft-ietf-behave-turn-10
decode_attr[0x0019] = function(...) return 'REQUESTED_TRANSPORT', decode_attr_string(...) end --}; % draft-ietf-behave-turn-10
decode_attr[0x001a] = function(...) return 'DONT_FRAGMENT', decode_attr_string(...) end --}; % draft-ietf-behave-turn-10
decode_attr[0x0020] = function(...) return 'XOR_MAPPED_ADDRESS' , decode_attr_xaddr(...) end --};
decode_attr[0x0022] = function(...) return 'RESERVATION_TOKEN', decode_attr_string(...) end --}; % draft-ietf-behave-turn-10
decode_attr[0x0024] = function(...) return 'PRIORITY', decode_attr_int(...) end --}; % draft-ietf-mmusic-ice-19
decode_attr[0x0025] = function(...) return 'USE_CANDIDATE', decode_attr_int(...) end--}; % draft-ietf-mmusic-ice-19
decode_attr[0x0026] = function(...) return 'PADDING', decode_attr_string(...) end --}; % draft-ietf-behave-nat-behavior-discovery-03
decode_attr[0x0027] = function(...) return 'RESPONSE_PORT', decode_attr_int(...) end --};
decode_attr[0x0028] = function(...) return 'XOR_REFLECTED_FROM', decode_attr_addr(...) end --}; % draft-ietf-behave-nat-behavior-discovery-03
decode_attr[0x0030] = function(...) return 'ICMP', decode_attr_string(...) end  --}; % Moved from TURN to a future I-D
decode_attr[0x8020] = function(...) return 'X_VOVIDA_XOR_MAPPED_ADDRESS', decode_attr_addr(...) end --}; % VOVIDA non-standart
decode_attr[0x8021] = function(...) return 'X_VOVIDA_XOR_ONLY', decode_attr_string(...) end--}; % VOVIDA non-standart
decode_attr[0x8022] = function(...) return 'SOFTWARE', decode_attr_string(...) end --}; % VOVIDA 'SERVER-NAME'
decode_attr[0x8023] = function(...) return 'ALTERNATE-SERVER', decode_attr_addr(...) end
decode_attr[0x8027] = function(...) return 'CACHE_TIMEOUT', decode_attr_string(...) end --}; % draft-ietf-behave-nat-behavior-discovery-03
--   decode_attr[0x8028] = function(...) return 'FINGERPRINT', decode_attr_string(...) end,
decode_attr[0x8029] = function(...) return 'ICE_CONTROLLED', decode_attr_int(...) end --}; % draft-ietf-mmusic-ice-19
decode_attr[0x802a] = function(...) return 'ICE_CONTROLLING', decode_attr_int(...) end --}; % draft-ietf-mmusic-ice-19
decode_attr[0x802b] = function(...) return 'RESPONSE_ORIGIN', decode_attr_addr(...) end
decode_attr[0x802c] = function(...) return 'OTHER_ADDRESS', decode_attr_addr(...) end
decode_attr[0x8050] = function(...) return 'X_VOVIDA_SECONDARY_ADDRESS', decode_attr_addr(...) end--}; % VOVIDA non-standart
decode_attr[0xc001] = function(...) return 'CONNECTION_REQUEST_BINDING', decode_attr_string(...) end
decode_attr[0xc002] = function(...) return 'BINDING_CHANGE', decode_attr_string(...) end


function stun_meta:encode()
   local req = self
   assert(req and type(req)=="table")
   assert(type(req.tx_id) == "number")
   local attrs_tbl = req.attrs
   local k,v,attrs
   attrs = ""
   for k,v in pairs(attrs_tbl) do
      if encode_attr[k] then
	attrs = attrs .. encode_attr[k](v)
      end
   end
   assert(req.class and req.method)
   local c1,m1 = req.class,req.method
   
   local str2method = {
      binding = 0x001 ,
      shared_secret = 0x002 ,
      allocate = 0x003,
      refresh = 0x004 ,
      connect = 0x005  ,
      send = 0x006  ,
      data = 0x007 ,
      createpermission = 0x008 ,
      channelbind = 0x009
   }
   local str2class = {
      request = 0 ,
      indication = 1  ,
      response = 2 ,
      error = 3 
   }
   
   c = str2class[c1]
   m = str2method[m1]
   
   -- hdecode_attr[0] = (c>>1) | ((m>>6)&0x3e)
   -- h[1] = ((c<<4) & 0x10) | ((m<<1)&0xe0) | (m&0x0f)
   assert(c and m)
   local s1 = bit.bor(bit.rshift(c,1),bit.band(bit.rshift(m,6),0x3e))
   local s2 = bit.bor(
      bit.band(bit.lshift(c,4),0x10),
      bit.band(bit.lshift(m,1),0xe0),
      bit.band(m,0x0f))
   local s_type = bit.bor(bit.lshift(s1,8),s2)
   local len = string.len(attrs)
   local f = ">IILA" 
   -- txid must long ,and 4 byte 0 + txid = 96 bit transactionid
   -- attrs = bin.pack(f,STUN_MAGIC_COOKIE,0,req.tx_id,data)
  
   local integrity_data = ""
   if req.key then
      len = len + 24 
      local data1 = bin.pack(">SSIILA",s_type,len,STUN_MAGIC_COOKIE,0,req.tx_id,attrs)
      local integrity = hmac.digest("sha1",data1,req.key)
      assert(#integrity ==40)
      --print(integrity)
      local first,second,last
      --integrity = tonumber(integrity,16)
      first = string.sub(integrity,1,8)
      first = tonumber(first,16)
      
      second = string.sub(integrity,9,-5)
      second = tonumber(second,16)
      
      last = string.sub(integrity,17,-1)
      last = tonumber(last,16)
      integrity_data = bin.pack(">SSLLI",0x0008,20,first,second,last)
   end
   
   attrs = attrs..integrity_data
   local finger_data = ""
   if req.fingerprint then
      len = len + 8 
      local data2 = bin.pack(">SSIILA",s_type,len,STUN_MAGIC_COOKIE,0,req.tx_id,attrs)
      local crc = bit32.bxor(crc32.hash(data2),0x5354554e)         
      finger_data = bin.pack(">SSI",0x8028,0x0004,crc)
   end
   attrs = attrs..finger_data
   local data = bin.pack(">SSIILA",s_type,len,STUN_MAGIC_COOKIE,0,req.tx_id,attrs)
   return data
end
function stun.decode(data,sz,key)
   local req = stun.new()
   local len = sz
   --local f = ">SSA" .. len..">CCCCI"
   local pos
   --check finger print
   if sz >= 20 + 8 then
      local msg,finger,crc,finger_len
      pos,msg,finger,finger_len,crc= bin.unpack(">A"..(sz-8).."SSI",data,sz)
      if finger == 0x8028 then
	 local crc1 = bit32.bxor(crc32.hash(msg),0x5354554e)
	 if crc1 ~= crc then
	    return false
	 end
	 req.fingerprint = true
      else
	 req.fingerprint = false
	 print("no crc was found in stun message")
      end
   else
      req.fingerprint = false
      print("no crc was found in stun message")
   end   
   pos = 0   
   --check integrity
   if key then
      local sz1 
      if req.fingerprint then
	 sz1 = sz - 8
      else
	 sz1 = sz
      end
      if sz1 < 20 + 24 then
	 return false
      end
      local f1,s1,l1
      local first,second,last
      --integrity = tonumber(integrity,16)
      f = ">A"..(sz1-24).."SSA20"
      local msg,t1,tlen
      pos,msg,t1,tlen,digest  = bin.unpack(f,data,sz)
      if t1==0x0008  then
	 local integrity
	 if req.fingerprint then
	    local pos,t2,l2,d3 = bin.unpack(">SSA"..(sz1-4-24),data,sz)
	    local l3 = l2-8 --remove fingerprint length
	    msg = bin.pack(">SSA",t2,l3,d3)
	 end
	 integrity= hmac.digest("sha1",msg,key)
	 first = string.sub(integrity,1,8)
	 first = tonumber(first,16)      
	 second = string.sub(integrity,9,-5)
	 second = tonumber(second,16)
	 last = string.sub(integrity,17,-1)
	 last = tonumber(last,16)
	 local digest1 = bin.pack(">LLI",first,second,last)
	 if digest1 == digest then
	    req.integrity = true
	 else
	    return false
	 end
      else
	 return false
      end
   end
   local pos,s_type,len,magic_cookie,tmp,tx_id = bin.unpack(">SSIIL",data,sz)
   if req.fingerprint then
      len = len - 8
   end
   if req.INTEGRITY then
      len = len -24
   end
   --hack google/msn data
   if s_type == 0x0115 then
      s_type =0x0017
   end
   
   --libnice stunmessage
   --(((t&0x3e00)>>2) | ((t&0x00e0)>>1) | (t&0x000f))
   local s_type1 = s_type
   local b1 =  bit.rshift(bit.band(s_type1,0x3e00),2)  
   local b2 =  bit.rshift(bit.band(s_type1,0x00e0),1)  
   local b3 = bit.band(s_type,0x000f)
   local method = bit.bor(b1,b2,b3)
   --(((t&0x0100)>>7)|((t&0x0010)>>4))
   local b4 = bit.rshift(bit.band(s_type,0x0100),7)
   local b5 = bit.rshift(bit.band(s_type,0x0010),4)
   local class = bit.bor(b4,b5)
   
   local method2str = {}
   method2str[0x001] = "binding"
   method2str[0x002] = "shared_secret"
   method2str[0x003] = "allocate"
   method2str[0x004] = "refresh"
   method2str[0x005] = "connect"
   method2str[0x006] = "send"
   method2str[0x007] = "data"
   method2str[0x008] = "createpermission"
   method2str[0x009] = "channelbind"
      
   req.method =  method2str[method]
   local class2str = {
      [0] = "request",
      [1] = "indication",
      [2] = "response",
      [3] = "error"
   }
   req.class = class2str[class]
   req.tx_id = tx_id
   
   pos = 21
   while pos < len + 20  do
      local t,type_len,tt
      pos,t,type_len= bin.unpack(">SS",data,sz,pos)      
      local f = decode_attr[t]
      if f ~= nil then
	 key,pos,value = f(data,type_len,sz,pos)
	 req.attrs[key] = value
      else
	 pos,tt = bin.unpack(">A"..type_len,pos)
	 req.attrs[t] = tt
	 print("warning unknow type:",t)
      end

     -- sz = sz - 4 - type_len
     -- len = len - 4 - type_len
   end
   return true,req
end

function stun.stun_test1()

end

return stun