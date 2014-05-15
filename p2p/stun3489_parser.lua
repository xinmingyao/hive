local bin = require "cell.binlib"
local p2p_lib = require "p2p.p2p_lib"
local assert = assert
local error  = error
local print = print
local tconcat = table.concat
local tinsert = table.insert
local srep = string.rep
local pairs = pairs
local tostring = tostring
local next = next

local MessageType = {
    BINDING_REQUEST     = 0x0001,
    BINDING_RESPONSE    = 0x0101,
}
local Attribute = {
    MAPPED_ADDRESS      = 0x0001,
    RESPONSE_ADDRESS    = 0x0002,
    CHANGE_REQUEST      = 0x0003,
    SOURCE_ADDRESS      = 0x0004,
    CHANGED_ADDRESS     = 0x0005,
    USERNAME        = 0x0006,
    PASSWORD        = 0x0007,
    MESSAGE_INTEGRITY   = 0x0008,
    ERROR_CODE      = 0x0009,
    UNKNOWN_ATTRIBUTES  = 0x000a,
    REFLECTED_FROM      = 0x000b,
    SERVER          = 0x8022
}
local magic=0x2112A443
--local magic = 0x2112A443 --rfc3489 
local parser = {}
local cookie = p2p_lib.stun_cookie --stun 0x0002 ice --for ice

parser.build_req = function (tx,attr)
   assert(tx and type(tx) == "number")
   local data = ""
   if attr then
      local k,v
      for k,v in pairs(attr) do
	 if v.length == 4 then
	    local f = ">SSI"
	    data = data .. bin.pack(f,v.type,v.length,v.value)
	 else
	    print("not suppport!!!!!")
	 end
      end
   end
   local txid = bin.pack(">IL",cookie,tx) --12 byte txid 4:type,8:ident

   local len = #data
   local req 
   if len > 0 then
      local f = ">SSIAA" 
      req = bin.pack(f,MessageType.BINDING_REQUEST,len,magic,txid,data)
   else
      local f = ">SSIA" 
      req = bin.pack(f,MessageType.BINDING_REQUEST,len,magic,txid)
   end

   return true,req
end

parser.is_stun3489 = function(data,sz)
   if sz >= 20 then
      local pos,type,length,magic,c,tx = bin.unpack(">SSIIL",data,sz)
      return m == magic and c == cookie
   end
   return false
end

parser.paser_rep = function(data,sz)
   local rep ={}
   local pos
   assert(sz >=20)
   pos,rep.type,rep.length,rep.magic,rep.cookie,rep.tx = bin.unpack(">SSIIL",data,sz)
   while( pos < sz ) do
      local t,len
      pos, t,len= bin.unpack(">SS", data,sz,pos)      
      local tt,family,port,ip
      if t == Attribute.MAPPED_ADDRESS then
	 pos,tt, family,port,ip = bin.unpack(">CCSI",data,sz,pos)
	 rep.external_ip = p2p_lib.fromdword(ip) 
	 rep.external_port = port
	 rep.external_family = family
      elseif t == Attribute.CHANGED_ADDRESS then
	 pos,tt, family,port,ip = bin.unpack(">CCSI",data,sz,pos)
	 rep.changed_ip = p2p_lib.fromdword(ip) 
	 rep.changed_port = port
	 rep.changed_family = family
      elseif t == Attribute.SOURCE_ADDRESS then
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

return parser
