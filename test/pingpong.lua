local cell = require "cell"
local crypto = require "crypto"
local digest = crypto.digest
local hmac = crypto.hmac
local base64 = require "base64"

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

function cell.main(msg,gui)
   local  key = "dGhlIHNhbXBsZSBub25jZQ=="
   key = key .. "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
   local value 
   local d = digest.new("sha1")
   local sha1 = d:final(key)
   local sha1 = crypto.digest("sha1",key,true)
   print(base64.encode("123456789123456789"))
   print(type(sha1))
--   print(base64.encode("123"))
   value = base64.encode(sha1)
   print(value)
    return msg
end
