local cell = require "cell"
local udp
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
	print("udp launched")
	udp = cell.open(9998,cell.self)
	return msg
end


cell.message {
    accept_udp = function(msg,len,peer_ip,peer_port)
      --local obj=cell.bind(fd)
      --obj:write(p,peer_ip,peer_port)
      print("receive from ",peer_ip,peer_port)
   end
}