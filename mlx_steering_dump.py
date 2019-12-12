#!/usr/bin/env python3

# Parse tool for SW steering debug dump file
# Written by valex@mellanox.com and Muhammads@mellanox.com

import sys
import os
import math
import argparse
import dr_parser
import dr_hw_ste_parser
import json
import dr_trigger

g_indent = 0
g_version = "1.0.0"
g_actions_str = ["decap L2",
		"encap L2",
		"decap L3",
		"encap L3",
		"drop",
		"dest QP",
		"dest FT",
		"counter",
		"tag",
		"modify header",
		"meter",
		"dest vport",
		"pop vlan",
		"push vlan" ]

def inc_indent():
	global g_indent
	g_indent += 1

def dec_indent():
	global g_indent
	g_indent -= 1

def print_dr(*args):
	global g_indent
	tab = "   " * g_indent
	print( tab+" ".join(map(str,args)))

def _srd(cur_dict, key):
	# Safe Read from Dict (SRD)
	if (key in cur_dict.keys()):
		return str(cur_dict[key])
	else:
		return "None"

def dict_join_str(in_dict):
	attrs = []
	for k, v in in_dict.items():
		attrs.append(str(k) + ": " +str(v))

	return ', '.join(attrs)

def read_dumps(file_name, verbose):
	try:
		phase = "file checks"
		if not (os.path.exists(file_name)):
			print_dr("File %s doesn't exist - use fullpath" % file_name)
			return {}

		# Print message for large files (100MB)
		if os.path.getsize(file_name) > pow(2, 26):
			print_dr("Loading large file, please wait...")

		phase = "read file"
		file = open(file_name, "r")
		txt = file.read()
		txt = txt.replace("\n", "")
		txt = txt.replace("}{", "},{")
		txt = "[" + txt + "]"
		file.close()

		phase = "evaluate file"
		dumps = json.loads(txt)
		if not isinstance(dumps, list):
			print_dr("Incompatible file format")
			return {}

	except Exception as e:
		print("Read dumps error (%s): %s" % (phase, e))
		return {}

	return dumps

def print_rule_actions(actions_types, actions_values):
	actions = []
	for i in range(len(actions_types)):
		action_str = g_actions_str[actions_types[i]]
		if actions_values[i] != "":
			action_str += " " + actions_values[i]

		actions.append(action_str)

	print_dr("actions: %s" % ", ".join(actions))

def parse_hw_stes(hw_stes):
	final = {}
	for hw_ste in hw_stes:
		parsed_ste = dr_hw_ste_parser.mlx5_hw_ste_parser(hw_ste)
		if "tag" not in parsed_ste.keys():
			continue

		clean_tag = dict(filter(lambda elem: eval(elem[1]) != 0, parsed_ste["tag"].items()))
		final.update(clean_tag)

	return dict_join_str(final)

def print_rule_ste_arr(rule, verbose):
	all_hw_stes = []
	for rx_tx in ["rx", "tx"]:
		if rx_tx in rule.keys():
			for ste in rule[rx_tx]["ste_arr"]:
				if "hw_ste" not in ste.keys():
					continue

				all_hw_stes.append(ste["hw_ste"])
				if verbose:
					print_dr("match (STE %s icm_idx %s): %s (%s)" % (
						rx_tx.upper(),
						_srd(ste, "icm_address"),
						_srd(ste, "hw_ste"),
						parse_hw_stes([ste["hw_ste"]])))

	print_dr("match: %s" % parse_hw_stes(all_hw_stes))

def print_rule_tree(rule, verbose):
	print_dr("rule %s:" % (_srd(rule, "handle")))

	inc_indent()
	print_rule_ste_arr(rule, verbose)
	if "actions_types" in rule.keys() and "actions_values" in rule.keys():
		print_rule_actions(rule["actions_types"], rule["actions_values"])
	dec_indent()

def print_rule_view(domain, table, matcher, rule, verbose):
	print_dr("rule %s: matcher %s, prio %s, table %s, level %s, domain: %s" % (
		_srd(rule, "handle"),
		_srd(matcher, "handle"),
		_srd(matcher, "priority"),
		_srd(table, "handle"),
		_srd(table, "level"),
		_srd(domain, "handle")))

	inc_indent()
	print_rule_ste_arr(rule, verbose)
	if "actions_types" in rule.keys() and "actions_values" in rule.keys():
		print_rule_actions(rule["actions_types"], rule["actions_values"])
	dec_indent()

def print_matcher_mask(mask):
	parsed_mask_final = {}
	sub_masks = ["outer", "inner", "misc", "misc2", "misc3"]
	sub_mask_parsers = [ dr_parser.dr_mask_spec_parser,
			     dr_parser.dr_mask_spec_parser,
			     dr_parser.dr_mask_misc_parser,
			     dr_parser.dr_mask_misc2_parser,
			     dr_parser.dr_mask_misc3_parser ]

	for sub_mask_index in range(len(sub_masks)):
		sub_mask = sub_masks[sub_mask_index]
		sub_mask_parser = sub_mask_parsers[sub_mask_index]
		input_mask = mask[sub_mask]
		if input_mask == "":
			continue

		# Parse the input mask
		parsed_mask = sub_mask_parser(input_mask)

		for k, v in list(parsed_mask.items()):
			# Remove empty keys
			if eval(v) == 0:
				del parsed_mask[k]
			else:
				if sub_mask == "inner":
					parsed_mask[sub_mask + "_" + k] = v
					del parsed_mask[k]

		# Merge to final dictionary
		parsed_mask_final.update(parsed_mask)

	print_dr("mask: %s" % dict_join_str(parsed_mask_final))

def print_domain_tree(domain, verbose):
	print_dr("domain %s: type: %s, gvmi: %s, num_vports: %s" % (
		_srd(domain, "handle"),
		_srd(domain, "type"),
		_srd(domain, "gvmi"),
		_srd(domain, "num_vports")))

	if (verbose):
		if "vports" in domain.keys():
			for vport in domain["vports"]:
				print_dr("vport: number %s, icm_addr_rx %15s icm_addr_tx %15s" % (
					_srd(vport, "vport_num"),
					_srd(vport, "icm_addr_rx"),
					_srd(vport, "icm_addr_tx")))

	if "tables" not in domain.keys():
		return 0

	inc_indent()
	for table in domain["tables"]:
		print_dr("table %s: level: %s, type: %s, id: %s" % (
			_srd(table, "handle"),
			_srd(table, "level"),
			_srd(table, "type") if _srd(table, "level") != "0" else "NONE",
			hex(int(_srd(table, "id"))) if _srd(table, "level") != "0" else "NONE"))

		if (verbose):
			print_dr("icm_addr_rx: %s icm_addr_tx: %s" % (\
				_srd(table["rx"], "s_anchor") if "rx" in table.keys() else "None",
				_srd(table["tx"], "s_anchor") if "tx" in table.keys() else "None"))

		if "matchers" not in table.keys():
			continue

		inc_indent()
		for matcher in table["matchers"]:
			print_dr("matcher %s: priority: %s" % (\
				_srd(matcher, "handle"), \
				_srd(matcher, "priority")))

			if (verbose):
				# TODO: Missing s_htbl
				print_dr("rx_builder_num: %s tx_builder_num: %s, rx_s_htbl_idx: %s, rx_e_anchor_idx: %s tx_s_htbl_idx: %s, tx_e_anchor_idx: %s" % (
					_srd(matcher["rx"], "builders_num") if "rx" in matcher.keys() else "None",
					_srd(matcher["tx"], "builders_num") if "tx" in matcher.keys() else "None",
					_srd(matcher["rx"], "s_anchor") if "rx" in matcher.keys() else "None",
					_srd(matcher["rx"], "e_anchor") if "rx" in matcher.keys() else "None",
					_srd(matcher["tx"], "s_anchor") if "tx" in matcher.keys() else "None",
					_srd(matcher["tx"], "e_anchor") if "tx" in matcher.keys() else "None"))
			
			inc_indent()
			print_matcher_mask(matcher["mask"])

			if "rules" not in matcher.keys():
				continue

			for rule in matcher["rules"]:
				print_rule_tree(rule, verbose)

			dec_indent()
		dec_indent()
	dec_indent()


def print_domain_rules(domain, verbose):
	if "tables" not in domain.keys():
		return 0

	for table in domain["tables"]:
		if "matchers" not in table.keys():
			continue

		for matcher in table["matchers"]:
			if "rules" not in matcher.keys():
				continue

			for rule in matcher["rules"]:
				print_rule_view(domain, table, matcher, rule, verbose)


def parse_args():
	parser = argparse.ArgumentParser(
	description='''mlx_steering_dump.py - Steering dump tool''')
	parser.add_argument('-f', dest="FILEPATH", default="", help='input steering dump file path')
	parser.add_argument('-d', dest="trigger", metavar=('pid', 'port'), nargs=2, help='Trigger DPDK app to generate json dump file (-d <APP PID> <PORT NUMBER>)')
	parser.add_argument('-t', action='store_true', default=False, dest='tree_view', help='tree view (default is rule view)')
	parser.add_argument('-v', action='store_true', default=False, dest='verbose', help='verbose output')
	parser.add_argument('-version', action='store_true', default=False, dest='version', help='show version')
	return parser.parse_args()

def main():
	args = parse_args()
	if (args.version):
		print_dr("Version %s" % g_version)
		return 0

	if (args.FILEPATH == ""):
		print_dr("No input steering dump file provided (-f FILEPATH)")
		return 0

	if (len(args.trigger) == 2):
		pid = int(args.trigger[0])
		port = int(args.trigger[1])
		dr_trigger.trigger_dump(pid, port, args.FILEPATH)
	elif(os.path.exists(args.FILEPATH) == False):
		print_dr("Input steering dump file doesn't exist")
		return 0
	
	dumps = read_dumps(args.FILEPATH, args.verbose)
	if (len(dumps) == 0):
		return -1

	for dump in dumps:
		if (args.tree_view):
			print_domain_tree(dump["domain"], args.verbose)
		else:
			print_domain_rules(dump["domain"], args.verbose)

	return 0

main()
