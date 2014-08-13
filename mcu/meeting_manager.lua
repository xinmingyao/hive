local cell = require "cell"
local meetings = {}

cell.command {
   join_meeting= function(data,user,gate)
      local mt_no = data.meeting_no
      print("meeting no",mt_no)
      assert(mt_no,"must have meetng no!")
      if not meetings[mt_no] then
	 local service = cell.cmd("launch","mcu.meeting",mt_no)
	 meetings[mt_no] = service
      end
      print("join",meetings[mt_no])
      local r2 = cell.call(meetings[mt_no],"join_meeting",user,gate)
      return true
   end
}
cell.message {
   chat = function(req)
      local mt_no = req.to
      assert(meetings[mt_no],"meeting does not exist")
      cell.send(meetings[mt_no],"chat",req.from,req.body)
   end
}
function cell.main(...)

end
