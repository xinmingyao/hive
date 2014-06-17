local cell = require "cell"
local stun = require "p2p.stun1"
cell.command {
	ping = function()
		cell.sleep(1)
		return "pong"
	end,
	sleep = function(T)
	      cell.sleep(T)
	      return true
	end
}

local csocket = require "cell.c.socket"

function test_class_methdo(C,M)
   local req = stun.new(C,M,9)
   local data = req:encode()
   local sz,msg = csocket.sendpack(data)
   local ok,req2 = stun.decode(msg,sz,key)
   assert(req2.class == C)
   assert(req2.method == M)
end
function cell.main(msg,gui)
   local req = stun.new("request","binding",9)
   req:add_attr('PRIORITY',1)
   req:add_attr('USERNAME',"test")
   req:add_attr('PASSWORD',"pwd")
   req:add_attr('USE_CANDIDATE',2)
   req:add_attr('ICE_CONTROLLED',3)
   req:add_attr('ICE_CONTROLLING',4)
   req:add_attr('XOR_MAPPED_ADDRESS',{ip="192.168.203.1",port=8080})
   local key = "test"
   req.fingerprint = true
   req.key = key
   local data = req:encode()
   local sz,msg = csocket.sendpack(data)
   local ok,req2 = stun.decode(msg,sz,key)
   assert(true==ok)
   assert(9==req2.tx_id)
   print(req2.attrs['PRIORITY'])
   assert(1==req2.attrs['PRIORITY'])
   assert(2==req2.attrs['USE_CANDIDATE'])
   assert(3==req2.attrs['ICE_CONTROLLED'])
   assert(4==req2.attrs['ICE_CONTROLLING'])
   local addr = req2.attrs['XOR_MAPPED_ADDRESS']
   print(addr.port,addr.ip)
   assert(addr.port == 8080)
   assert(addr.ip == "192.168.203.1")
   print(req2.class)
   assert(req2.class == "request")
   assert(req2.method == "binding")
   test_class_methdo("request","binding")
   test_class_methdo("response","binding")
   test_class_methdo("error","binding")
   return 
end
