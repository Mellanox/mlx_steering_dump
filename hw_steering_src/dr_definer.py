dr_definers = {
"ib_l4": [[('opcode', 8), ('qp', 24)], [('se', 1), ('migreq', 1), ('ackreq', 1), ('fecn', 1), ('becn', 1), ('bth', 1), ('deth', 1), ('dcceth', 1), ('reserved_at_28', 2), ('pad_count', 2), ('tver', 4), ('p_key', 16)], [('reserved_at_40', 8), ('deth_source_qp', 24)]],
"eth_l4": [[('source_port', 16), ('destination_port', 16)], [('data_offset', 4), ('l4_ok', 1), ('l3_ok', 1), ('ip_fragmented', 1), ('tcp_ns', 1), ('tcp_cwr', 1), ('tcp_ece', 1), ('tcp_urg', 1), ('tcp_ack', 1), ('tcp_psh', 1), ('tcp_rst', 1), ('tcp_syn', 1), ('tcp_fin', 1), ('first_fragment', 1), ('reserved_at_31', 15)]],
"eth_l2": [[('dmac_47_16', 32)], [('dmac_15_0', 16), ('l3_ethertype', 16)], [('reserved_at_40', 1), ('sx_sniffer', 1), ('functional_lb', 1), ('ip_fragmented', 1), ('qp_type', 2), ('encap_type', 2), ('port_number', 2), ('l3_type', 2), ('l4_type_bwc', 2), ('first_vlan_qualifier', 2), ('first_priority', 3), ('first_cfi', 1), ('first_vlan_id', 12)], [('l4_type', 4), ('reserved_at_64', 2), ('ipsec_layer', 2), ('l2_type', 2), ('force_lb', 1), ('l2_ok', 1), ('l3_ok', 1), ('l4_ok', 1), ('second_vlan_qualifier', 2), ('second_priority', 3), ('second_cfi', 1), ('second_vlan_id', 12)]],
"eth_l3": [[('ip_version', 4), ('ihl', 4), ('dscp', 6), ('ecn', 2), ('time_to_live_hop_limit', 8), ('protocol_next_header', 8)], [('identification', 16), ('flags', 3), ('fragment_offset', 13)], [('ipv4_total_length', 16), ('checksum', 16)], [('reserved_at_60', 12), ('flow_label', 20)], [('packet_length', 16), ('ipv6_payload_length', 16)]],
"ib_l2": [[('sx_sniffer', 1), ('force_lb', 1), ('functional_lb', 1), ('reserved_at_3', 3), ('port_number', 2), ('sl', 4), ('qp_type', 2), ('lnh', 2), ('dlid', 16)], [('vl', 4), ('lrh_packet_length', 12), ('slid', 16)]],
"eth_l2_src": [[('smac_47_16', 32)], [('smac_15_0', 16), ('loopback_syndrome', 8), ('l3_type', 2), ('l4_type_bwc', 2), ('first_vlan_qualifier', 2), ('ip_fragmented', 1), ('functional_lb', 1)]],
"ipv4_src_dst": [[('source_address', 32)], [('destination_address', 32)]],
"ipv6_addr": [[('ipv6_address_127_96', 32)], [('ipv6_address_95_64', 32)], [('ipv6_address_63_32', 32)], [('ipv6_address_31_0', 32)]],
"flex_parser": [[('version', 3), ('proto_type', 1), ('reserved1', 1), ('ext_hdr_flag', 1), ('seq_num_flag', 1), ('pdu_flag', 1), ('msg_type', 8), ('msg_len', 8), ('teid', 32), ('seq_num', 16), ('pdu_num', 8), ('next_ext_hdr_type', 8), ('len', 8)]],
"oks2": [[('reserved_at_0', 10), ('second_mpls_ok', 1), ('second_mpls4_s_bit', 1), ('second_mpls4_qualifier', 1), ('second_mpls3_s_bit', 1), ('second_mpls3_qualifier', 1), ('second_mpls2_s_bit', 1), ('second_mpls2_qualifier', 1), ('second_mpls1_s_bit', 1), ('second_mpls1_qualifier', 1), ('second_mpls0_s_bit', 1), ('second_mpls0_qualifier', 1), ('first_mpls_ok', 1), ('first_mpls4_s_bit', 1), ('first_mpls4_qualifier', 1), ('first_mpls3_s_bit', 1), ('first_mpls3_qualifier', 1), ('first_mpls2_s_bit', 1), ('first_mpls2_qualifier', 1), ('first_mpls1_s_bit', 1), ('first_mpls1_qualifier', 1), ('first_mpls0_s_bit', 1), ('first_mpls0_qualifier', 1)]],
"oks1": [[('second_ipv4_checksum_ok', 1), ('second_l4_checksum_ok', 1), ('first_ipv4_checksum_ok', 1), ('first_l4_checksum_ok', 1), ('second_l3_ok', 1), ('second_l4_ok', 1), ('first_l3_ok', 1), ('first_l4_ok', 1), ('flex_parser7_steering_ok', 1), ('flex_parser6_steering_ok', 1), ('flex_parser5_steering_ok', 1), ('flex_parser4_steering_ok', 1), ('flex_parser3_steering_ok', 1), ('flex_parser2_steering_ok', 1), ('flex_parser1_steering_ok', 1), ('flex_parser0_steering_ok', 1), ('second_ipv6_extension_header_vld', 1), ('first_ipv6_extension_header_vld', 1), ('l3_tunneling_ok', 1), ('l2_tunneling_ok', 1), ('second_tcp_ok', 1), ('second_udp_ok', 1), ('second_ipv4_ok', 1), ('second_ipv6_ok', 1), ('second_l2_ok', 1), ('vxlan_ok', 1), ('gre_ok', 1), ('first_tcp_ok', 1), ('first_udp_ok', 1), ('first_ipv4_ok', 1), ('first_ipv6_ok', 1), ('first_l2_ok', 1)]],
"src_qp_gvmi": [[('loopback_syndrome', 8), ('l3_type', 2), ('l4_type_bwc', 2), ('first_vlan_qualifier', 2), ('reserved_at_e', 1), ('functional_lb', 1), ('source_gvmi', 16)], [('force_lb', 1), ('ip_fragmented', 1), ('source_is_requestor', 1), ('reserved_at_23', 5), ('source_qp', 24)]],
"voq": [[('reserved_at_0', 24), ('ecn_ok', 1), ('congestion', 1), ('profile', 2), ('internal_prio', 4)]],
}
