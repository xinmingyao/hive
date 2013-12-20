local cell = require "cell"

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
	print("pingpong launched",gui[1])
	return msg
end
