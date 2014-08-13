local cell = require "cell"
local users = {}
local meeting_no
cell.command {
   join_meeting= function(user,gate)
      print(user,gate)
      local list = {}
      for k,v in pairs(users) do
	 cell.send(v.gate,"join_meeting",user)
	 table.insert(list,k)
      end
      users[user] = {gate=gate}
      if #list then
	 cell.send(gate,"list_user",list)
      end
      return true
   end
}

cell.message {
   chat = function(from,data)
      for k,v in pairs(users) do
	 if k ~= from then
	    cell.send(v.gate,"chat",from,data)
	 end
      end
   end
}

function cell.main(...)
   meeting_no = ...
   print("start meetint:",meeting_no)
end
