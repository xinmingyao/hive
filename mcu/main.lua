local cell = require "cell"
local crypto = require "crypto"
local digest = crypto.digest
local hmac = crypto.hmac
local base64 = require "base64"
local c = require "cell.c"
cell.command {
	ping = function()
		return "pong"
	end,
	sleep = function(T)
	      cell.sleep(T)
	      return true
	end
}
local meeting_manager
function cell.main()
   local meeting_manager = cell.cmd("launch","mcu.meeting_manager")
   local ws_gate = cell.cmd("launch","mcu.ws_gate")
end
