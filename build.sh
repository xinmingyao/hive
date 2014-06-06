BASEDIR = "$PWD"
cd deps/lpeg 
make
cp lpeg.so ../../ 

cd deps/luasec/
make
cp src/ssl.so ../../
cp src/ssl.lua ../../
