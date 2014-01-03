package.cpath = package.cpath .. ";./?.dylib"
local main = ...
local hive = require "hive"
if not main then
   main = "test.main"
end
hive.start {
   thread = 4,
   main = main,
}

