local cell = require "cell"

--code from skynet
-- It's a simple service exit monitor, you can do something more when a service exit.

local service_map = {}

cell.dispatch {
	id = 8,
	replace = true,
	dispatch = function(address)
		local w = service_map[address]
		if w then
			for watcher in pairs(w) do
				cell.rawsend(watcher,8,address)
			end
			service_map[address] = false
		end
		print("exit cell:",address)
	end
}

cell.command {
	monitor = function(watcher,service)
		local w = service_map[service]
		if not w then
			if w == false then
				return false
			end
			w = {}
			service_map[service] = w
		end
		w[watcher] = true
		return true
	end
}

function cell.main()
	 print("start monitor:",cell.self)
	 cell.register_monitor()
	 return true
end 
