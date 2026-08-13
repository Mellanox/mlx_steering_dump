# Copyright (c) 2026 NVIDIA CORPORATION.  All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Hash table statistics for a SW steering dump.

Software steering resolves a rule through a chain of hash tables, one per
matcher builder. A rule hashes to an entry of the table, and when that entry
is already taken by a different tag the driver allocates a single entry table
for the new STE and links it to the entry that was hit, forming a miss list.
Those linked STEs are the collisions this module counts.

Nothing in the dump says which STEs collided, so the miss lists are rebuilt
from the STE control fields: an STE whose miss address points at another STE
of the same hash table is followed by that STE, and every other miss address,
the matcher end anchor included, ends the chain.
"""

from src.dr_constants import *
from src.dr_utilities import hex_2_bin


def hit_location_calc(next_table_base_39_32, next_table_base_31_5):
    """
    Split an STE hit address into the base and the size of the table it points
    at. The two fields hold one value whose lowest set bit is the size of the
    table and whose remaining bits are its base. The extra shift right brings
    the base from bits 31:5 to the icm_idx units the dump uses for STE
    addresses.
    :param next_table_base_39_32: Bits 39:32 of the hit address
    :param next_table_base_31_5: Bits 31:5 of the hit address
    :return: (base, size) of the pointed table
    """
    address = (next_table_base_39_32 << 27) | next_table_base_31_5
    size = ((address ^ (address - 1)) + 1) >> 1
    base = (address & (address - 1)) >> 1

    return base, size


def parse_ste_ctrl(ste_data):
    """
    Decode the control fields that place an STE in the steering tree. The bit
    offsets are those of the v1 entry formats, see dr_ste_v1_parser.py. The
    miss address is held as bits 39:32 and 31:6, so it needs no rescaling to
    match the STE addresses of the dump.
    :param ste_data: Raw STE bytes as dumped, in hex
    :return: (miss address, base of the pointed table, size of that table)
    """
    bin_str = hex_2_bin(ste_data)
    miss_addr = (int(bin_str[56: 64], 2) << 26) | int(bin_str[64: 90], 2)
    base, size = hit_location_calc(int(bin_str[120: 128], 2),
                                   int(bin_str[128: 155], 2))

    return miss_addr, base, size


class dr_htbl_statistics():
    """
    Occupancy and collisions of a single hash table of a matcher.
    """
    def __init__(self, level, base, size):
        self.level = level
        self.base = base
        self.size = size
        self.chains = []

    def get_num_of_stes(self):
        return sum(len(chain) for chain in self.chains)

    def get_num_of_used_entries(self):
        return len(self.chains)

    def get_num_of_collisions(self):
        return self.get_num_of_stes() - self.get_num_of_used_entries()

    def get_distribution(self):
        """
        Number of STEs per miss list depth. Index 0 counts the STEs that were
        placed on the entry they hashed to, index 1 those that were pushed one
        collision further, and so on.
        """
        distribution = [0] * max([len(c) for c in self.chains], default=0)
        for chain in self.chains:
            for depth in range(len(chain)):
                distribution[depth] += 1

        return distribution


def _get_match_stes(rule, entry_rec_type, num_of_builders):
    """
    The match STEs of a rule, in chain order. Every rule of a matcher walks
    num_of_builders match STEs, so any entry past them was added to carry
    actions that did not fit on the last match STE and is left out.
    :param rule: dr_dump_rule object
    :param entry_rec_type: Rule entry record type of the direction to collect
    :param num_of_builders: Number of match STEs of the matcher
    :return: List of the rule entry objects that hold match STEs
    """
    entries = [e for e in rule.rule_entry_list
               if e.data["dr_dump_rec_type"] == entry_rec_type]

    return entries[:num_of_builders]


def _get_htbls(matcher, matcher_rx_tx, entry_rec_type):
    """
    Collect the match STEs of every rule of the matcher into the hash tables
    that hold them. A hash table is identified by the STE pointing at it, so
    the STEs of one level can be spread over several tables once the tree
    branches. STEs are keyed by their address, which folds an STE that several
    rules share back into one.
    :param matcher: dr_dump_matcher object
    :param matcher_rx_tx: Its dr_dump_matcher_rx_tx object of that direction
    :param entry_rec_type: Rule entry record type of that direction
    :return: {(level, address of the pointing STE): {STE address: STE ctrl}}
    """
    num_of_builders = int(matcher_rx_tx.data["num_of_builders"])
    htbls = {}

    for rule in matcher.rule_list:
        stes = _get_match_stes(rule, entry_rec_type, num_of_builders)
        for level, entry in enumerate(stes, start=1):
            addr = int(entry.data["ste_icm_addr"], 16)
            parent = int(stes[level - 2].data["ste_icm_addr"], 16) \
                     if level > 1 else None
            htbls.setdefault((level, parent), {})[addr] = \
                parse_ste_ctrl(entry.data["ste_data"])

    return htbls


def _get_htbl_geometry(matcher_rx_tx, parent, members):
    """
    Base and size of the hash table holding the given STEs. The first level is
    described by the matcher itself, and its size is only dumped for a matcher
    of a fixed size. Any deeper table is described by the STE pointing at it.
    :param matcher_rx_tx: dr_dump_matcher_rx_tx object of that direction
    :param parent: Address of the pointing STE, None on the first level
    :param members: {STE address: STE ctrl} of the tables of the whole matcher
    :return: (base, size), size is None when the dump does not hold it
    """
    if parent is None:
        chunk_size = matcher_rx_tx.data.get("chunk_size")
        size = 1 << int(chunk_size) if chunk_size not in (None, "-1") else None
        return int(matcher_rx_tx.data["s_htbl"], 16), size

    _, base, size = members[parent]

    return base, size


def _get_chains(members):
    """
    Rebuild the miss lists of one hash table. An STE whose miss address is
    another STE of the same table was linked there on a collision, so it is
    the successor of that STE. Every other miss address ends a chain.
    :param members: {STE address: STE ctrl} of one hash table
    :return: List of chains, each a list of STE addresses, head first
    """
    successor = {addr: ctrl[0] for addr, ctrl in members.items()
                 if ctrl[0] in members}
    chains = []

    for addr in members:
        if addr in successor.values():
            continue

        chain = [addr]
        while chain[-1] in successor:
            next_addr = successor[chain[-1]]
            if next_addr in chain:
                break
            chain.append(next_addr)
        chains.append(chain)

    return chains


def get_matcher_statistics(matcher, matcher_rx_tx, entry_rec_type):
    """
    Hash table statistics of one direction of a matcher.
    :param matcher: dr_dump_matcher object
    :param matcher_rx_tx: Its dr_dump_matcher_rx_tx object of that direction
    :param entry_rec_type: Rule entry record type of that direction
    :return: List of dr_htbl_statistics, ordered by level
    """
    htbls = _get_htbls(matcher, matcher_rx_tx, entry_rec_type)
    all_members = {}
    for members in htbls.values():
        all_members.update(members)

    statistics = []
    for (level, parent), members in sorted(htbls.items()):
        base, size = _get_htbl_geometry(matcher_rx_tx, parent, all_members)
        htbl = dr_htbl_statistics(level, base, size)
        htbl.chains = _get_chains(members)
        statistics.append(htbl)

    return statistics
