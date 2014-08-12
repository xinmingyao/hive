local tool ={}

function tool.deep_copy(src,dst)
   local mt = getmetatable(dst)
   if mt then
      setmetatable(src,mt)
   end
   local k,v
   for k,v in pairs(dst) do
      if type(v) == "table" then
	 local v1 = {}
	 deep_copy(v1,v)
	 src[k] = v1
      else
	 src[k] = v
      end
   end
   local i
   for i in ipairs(dst) do
      local v = dst[i]
      if type(v) == "table" then
	 local v1 = {}
	 deep_copy(v1,v)
	 src[i] = v1
      else
	 src[i] = v
      end
   end
end

return tool
