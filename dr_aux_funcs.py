# Written by valex@mellanox.com and Muhammads@mellanox.com

def pretty_ipv4(ip):
	ipaddr = "%i.%i.%i.%i" % (int(ip[2:4],16),int(ip[4:6],16),
				  int(ip[6:8],16),int(ip[8:10],16))
	return ipaddr

def pretty_mac(mac):
	mac_addr = "%s:%s:%s:%s:%s:%s" % (mac[2:4], mac[4:6], mac[6:8],
					  mac[8:10], mac[10:12], mac[12:14])
	return mac_addr

def pretty_ip_protocol(p):
	switch = { 0x06 : "TCP",
		   0x11 : "UDP", 
		   0x2f : "GRE",
		   0x33 : "IPSEC",
		 }

	protcol = int(p, 16)
	if protcol in switch.keys():
		return switch[protcol]
	else:
		return p

def prettify_fields(dic):
	for j in dic.keys():
		if "ip_protocol" in j:
			dic[j] = pretty_ip_protocol(dic[j])
			continue
		if "src_ip" in j or "dst_ip" in j:
			dic[j] = pretty_ipv4(dic[j])

		if "smac" in j or "dmac" in j:
			dic[j] = pretty_mac(dic[j])

def prettify_tag(tag):
	clean_tag = dict(filter(lambda elem: eval(elem[1]) != 0, tag.items()))
	prettify_fields(clean_tag)	
	return clean_tag

def prettify_mask(mask):
	clean_mask = dict(filter(lambda elem: eval(elem[1]) != 0, mask.items()))
	return clean_mask
