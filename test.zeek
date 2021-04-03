global addrTable :table[addr] of set[string] = table();

event http_header(c:connection,is_orig:bool,name:string,value:string)
{
	local src_addr:addr = c$id$orig_h;
	if(name == "USER-AGENT")
	{
		local useragent:string = to_lower(value);
		if (src_addr in addrTable) {
			add addrTable[src_addr][useragent];
		} else {
			addrTable[src_addr] = set(useragent);
		}
	}
}

event zeek_done()
	{
		for (src_addr in addrTable) {
		if (|addrTable[src_addr]| >= 3) {
			print(addr_to_uri(src_addr) + " is a proxy");
		}
	}
	}
