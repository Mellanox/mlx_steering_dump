# Written by valex@mellanox.com and Muhammads@mellanox.com

def little_endian_32(hex_str):
	data = ""
	for i in range(0, len(hex_str), 8):
		data += hex_str[i + 6: i + 8] + hex_str[i+4: i+6] + \
			hex_str[i+2: i+4] + hex_str[i: i+2]
	return data


def hex_2_bin(hex_str):
	arr = {"0": "0000", "1": "0001", "2": "0010", "3": "0011",
		   "4": "0100", "5": "0101", "6": "0110", "7": "0111",
		   "8": "1000", "9": "1001", "a": "1010", "b": "1011",
		   "c": "1100", "d": "1101", "e": "1110", "f": "1111"}
	bin_str = ""
	for i in range(0, len(hex_str)):
		bin_str += arr[hex_str[i]]
	return bin_str


def get_bits_at(data, i, j, m, n):
	bin_val = hex_2_bin(data[i: j])
	bin_val = hex(int(bin_val[m: n], 2))
	return bin_val


def _val(field_str):
	return "0x" + field_str


def dr_mask_spec_parser(mask):
	ret = {}
	data = ""
	for i in range(0, len(mask), 8):
		tmp = little_endian_32(mask[i: i + 8])
		data += tmp
	ret["smac"] = _val(data[0: 8] + data[8: 12])
	ret["ethertype"] = _val(data[12: 16])
	ret["dmac"] = _val(data[16: 24] + data[24: 28])
	ret["first_vid"] = get_bits_at(data, 24, 32, 20, 32)
	ret["first_cfi"] = get_bits_at(data, 24, 32, 19, 20)
	ret["first_prio"] = get_bits_at(data, 24, 32, 16, 19)
	ret["tcp_flags"] = get_bits_at(data, 32, 40, 23, 32)
	ret["ip_version"] = get_bits_at(data, 32, 40, 19, 23)
	ret["frag"] = get_bits_at(data, 32, 40, 18, 19)
	ret["svlan_tag"] = get_bits_at(data, 32, 40, 17, 18)
	ret["cvlan_tag"] = get_bits_at(data, 32, 40, 16, 17)
	ret["ip_ecn"] = get_bits_at(data, 32, 40, 14, 16)
	ret["ip_dscp"] = get_bits_at(data, 32, 40, 8, 14)
	ret["ip_protocol"] = get_bits_at(data, 32, 40, 0, 8)
	ret["tcp_dport"] = _val(data[44: 48])
	ret["tcp_sport"] = _val(data[40: 44])
	ret["ip_ttl_hoplimit"] = get_bits_at(data, 48, 56, 24, 32)
	ret["reserved"] = get_bits_at(data, 48, 56, 0, 24)
	ret["udp_dport"] = _val(data[60: 64])
	ret["udp_sport"] = _val(data[56: 60])

	if eval(_val(data[88: 96])) == eval(_val(data[64: 96])):
		ret["src_ip"] = _val(data[88: 96])  # IPV4
	else:
		ret["src_ip"] = _val(data[64: 96])  # IPV6

	if eval(_val(data[120: 128])) == eval(_val(data[96: 128])):
		ret["dst_ip"] = _val(data[120: 128])  # IPV4
	else:
		ret["dst_ip"] = _val(data[96: 128])  # IPV6

	return ret


def dr_mask_misc_parser(mask):
	ret = {}
	data = ""
	for i in range(0, len(mask), 8):
		tmp = little_endian_32(mask[i: i + 8])
		data += tmp
	ret["source_sqn"] = get_bits_at(data, 0, 8, 8, 32)
	ret["source_vhca_port"] = get_bits_at(data, 0, 8, 4, 8)
	ret["gre_s_present"] = get_bits_at(data, 0, 8, 3, 4)
	ret["gre_k_present"] = get_bits_at(data, 0, 8, 2, 3)
	ret["reserved_auto1"] = get_bits_at(data, 0, 8, 1, 2)
	ret["gre_c_present"] = get_bits_at(data, 0, 8, 0, 1)
	ret["source_port"] = _val(data[12: 16])
	ret["reserved_auto2"] = _val(data[8: 12])
	ret["inner_second_vid"] = get_bits_at(data, 16, 24, 20, 32)
	ret["inner_second_cfi"] = get_bits_at(data, 16, 24, 19, 20)
	ret["inner_second_prio"] = get_bits_at(data, 16, 24, 16, 19)
	ret["outer_second_vid"] = get_bits_at(data, 16, 24, 4, 16)
	ret["outer_second_cfi"] = get_bits_at(data, 16, 24, 3, 4)
	ret["outer_second_prio"] = get_bits_at(data, 16, 24, 0, 3)
	ret["gre_protocol"] = _val(data[28: 32])
	ret["reserved_auto3"] = get_bits_at(data, 24, 32, 4, 16)
	ret["inner_second_svlan_tag"] = get_bits_at(data, 24, 32, 3, 4)
	ret["outer_second_svlan_tag"] = get_bits_at(data, 24, 32, 2, 3)
	ret["inner_second_cvlan_tag"] = get_bits_at(data, 24, 32, 1, 2)
	ret["outer_second_cvlan_tag"] = get_bits_at(data, 24, 32, 0, 1)
	ret["gre_key_l"] = get_bits_at(data, 32, 40, 24, 32)
	ret["gre_key_h"] = get_bits_at(data, 32, 40, 0, 24)
	ret["reserved_auto4"] = get_bits_at(data, 40, 48, 24, 32)
	ret["vxlan_vni"] = get_bits_at(data, 40, 48, 0, 24)
	ret["geneve_oam"] = get_bits_at(data, 48, 56, 31, 32)
	ret["reserved_auto5"] = get_bits_at(data, 48, 56, 24, 31)
	ret["geneve_vni"] = get_bits_at(data, 48, 56, 0, 24)
	ret["outer_ipv6_flow_label"] = get_bits_at(data, 56, 64, 12, 32)
	ret["reserved_auto6"] = get_bits_at(data, 56, 64, 0, 12)
	ret["inner_ipv6_flow_label"] = get_bits_at(data, 64, 72, 12, 32)
	ret["reserved_auto7"] = get_bits_at(data, 64, 72, 0, 12)
	ret["geneve_protocol_type"] = _val(data[76: 80])
	ret["geneve_opt_len"] = get_bits_at(data, 72, 80, 10, 16)
	ret["reserved_auto8"] = get_bits_at(data, 72, 80, 0, 10)
	ret["bth_dst_qp"] = get_bits_at(data, 80, 88, 8, 32)
	ret["reserved_auto9"] = get_bits_at(data, 80, 88, 0, 8)
	return ret


def dr_mask_misc2_parser(mask):
	ret = {}
	data = ""
	for i in range(0, len(mask), 8):
		tmp = little_endian_32(mask[i: i + 8])
		data += tmp
	ret["outer_first_mpls_ttl"] = get_bits_at(data, 0, 8, 24, 32)
	ret["outer_first_mpls_s_bos"] = get_bits_at(data, 0, 8, 23, 24)
	ret["outer_first_mpls_exp"] = get_bits_at(data, 0, 8, 20, 23)
	ret["outer_first_mpls_label"] = get_bits_at(data, 0, 8, 0, 20)
	ret["inner_first_mpls_ttl"] = get_bits_at(data, 8, 16, 24, 32)
	ret["inner_first_mpls_s_bos"] = get_bits_at(data, 8, 16, 23, 24)
	ret["inner_first_mpls_exp"] = get_bits_at(data, 8, 16, 20, 23)
	ret["inner_first_mpls_label"] = get_bits_at(data, 8, 16, 0, 20)
	ret["outer_first_mpls_over_gre_ttl"] = get_bits_at(data, 16, 24, 24, 32)
	ret["outer_first_mpls_over_gre_s_bos"] = get_bits_at(data, 16, 24, 23, 24)
	ret["outer_first_mpls_over_gre_exp"] = get_bits_at(data, 16, 24, 20, 23)
	ret["outer_first_mpls_over_gre_label"] = get_bits_at(data, 16, 24, 0, 20)
	ret["outer_first_mpls_over_udp_ttl"] = get_bits_at(data, 24, 32, 24, 32)
	ret["outer_first_mpls_over_udp_s_bos"] = get_bits_at(data, 24, 32, 23, 24)
	ret["outer_first_mpls_over_udp_exp"] = get_bits_at(data, 24, 32, 20, 23)
	ret["outer_first_mpls_over_udp_label"] = get_bits_at(data, 24, 32, 0, 20)
	ret["metadata_reg_c_7"] = _val(data[32: 40])
	ret["metadata_reg_c_6"] = _val(data[40: 48])
	ret["metadata_reg_c_5"] = _val(data[48: 56])
	ret["metadata_reg_c_4"] = _val(data[56: 64])
	ret["metadata_reg_c_3"] = _val(data[64: 72])
	ret["metadata_reg_c_2"] = _val(data[72: 80])
	ret["metadata_reg_c_1"] = _val(data[80: 88])
	ret["metadata_reg_c_0"] = _val(data[88: 96])
	ret["metadata_reg_a"] = _val(data[96: 104])
	ret["metadata_reg_b"] = _val(data[104: 112])
	return ret


def dr_mask_misc3_parser(mask):
	ret = {}
	data = ""
	for i in range(0, len(mask), 8):
		tmp = little_endian_32(mask[i: i + 8])
		data += tmp
	ret["inner_tcp_seq_num"] = _val(data[0: 8])
	ret["outer_tcp_seq_num"] = _val(data[8: 16])
	ret["inner_tcp_ack_num"] = _val(data[16: 24])
	ret["outer_tcp_ack_num"] = _val(data[24: 32])
	ret["outer_vxlan_gpe_vni"] = get_bits_at(data, 32, 40, 8, 32)
	ret["reserved_auto1"] = get_bits_at(data, 32, 40, 0, 8)
	ret["reserved_auto2"] = _val(data[44: 48])
	ret["outer_vxlan_gpe_flags"] = get_bits_at(data, 40, 48, 8, 16)
	ret["outer_vxlan_gpe_next_protocol"] = get_bits_at(data, 40, 48, 0, 8)
	ret["icmpv4_header_data"] = _val(data[48: 56])
	ret["icmpv6_header_data"] = _val(data[56: 64])
	ret["icmpv6_code"] = get_bits_at(data, 64, 72, 24, 32)
	ret["icmpv6_type"] = get_bits_at(data, 64, 72, 16, 24)
	ret["icmpv4_code"] = get_bits_at(data, 64, 72, 8, 16)
	ret["icmpv4_type"] = get_bits_at(data, 64, 72, 0, 8)
	return ret
