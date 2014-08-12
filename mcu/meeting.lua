local cell = require "cell"
local users = {}

cell.command {
   join_meeting= function(user,gate)
      for k,v in ipairs() do
	 cell.send(v.gate,"join_meeting",user)
      end
      users[user] = {gate=gate}
      return true
   end
}
function cell.main(...)

end
