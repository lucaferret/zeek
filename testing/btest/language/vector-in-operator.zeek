# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

local ten = "0123456789";
local vec: vector of string = { "zero", "one" };
local n = 0;
vec[5] = "five";
vec[7] = "seven";
print vec;

for ( i in vec )
	vec[i] += ".exe";

for ( c in ten )
	{
	local is_set: bool = (n in vec);
	print fmt("vec[%s] = %s", n, is_set ? vec[n] : "<not set>");
	++n;
	}
