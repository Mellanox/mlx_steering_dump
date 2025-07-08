#!/bin/bash

# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 Nvidia, Inc. All rights reserved. See COPYING file

###### Initial values
mst_dev="-1"
gvmi="-1"
portid="-1"
size=1
index=-1
res_type=0
pretty=0
res_dump_supp=0
port="0"
tool=""
parsing="parsed"
verbosity="0"
ste_version="" #CONNECTX_5=0x0, CONNECTX_6DX=0x1

icmd_opcode_busy_addr="0x23fc.0:32"
icmd_busy_addr="0x23fc.0:1"
icmd_status_addr="0x23fc.8:8"
opcode="8001"
icmd_start_addr="0x2000"
icmd_gvmi_addr="0x2040.0:16"
icmd_rw_addr="0x2040.31:1"
icmd_ctx_type_addr="0x2044.0:16"
icmd_index_hi_addr="0x2048.0:32"
icmd_index_lo_addr="0x204c.0:32"
icm_ctx_icm_num2_addr="0x2050.0:32"

function ste_parser {
	local ste_raw=$1

	python ste_dumper_utils.py $ste_version $ste_raw $index $verbosity
}	

###### read_res_icmd
# Read resource using icmd
# NOTE: Resource type (res_type) is not guaranteed to be compatible between FW.
############
function read_res_icmd {
	local mst_dev=$1
	local gvmi=$2
	local res_type=$3
	local res_num=$4

	sudo mcra $mst_dev $icmd_opcode_busy_addr $opcode
	sudo mcra $mst_dev $icmd_gvmi_addr	  $(( gvmi ))
	sudo mcra $mst_dev $icmd_index_hi_addr $(( res_num >> 32 ))
	sudo mcra $mst_dev $icmd_index_lo_addr $(( res_num & 0xffffffff ))
	sudo mcra $mst_dev $icmd_ctx_type_addr $(( res_type ))
	sudo mcra $mst_dev $icmd_rw_addr 1
	sudo mcra $mst_dev $icm_ctx_icm_num2_addr 0
	sudo mcra $mst_dev $icmd_busy_addr 1

	sleep 0.5
	local busy=`sudo mcra $mst_dev $icmd_busy_addr`
	while [ $(( busy )) -ne 0 ] ; do busy=`sudo mcra $mst_dev $icmd_busy_addr`;  sleep 0.1 ; done

	local status=`sudo mcra $mst_dev $icmd_status_addr`
	if [ "$status" != "0x00000000" ] ; then
		echo  "ERROR: icmd failed, (status=$status);"
		return;
	fi
}

###### get_gvmi_counter
# Read counter using icmd
############
function get_gvmi_counter {
	local l_mst_dev=$1
	local l_port=$2
	local l_gvmi=$3
	local l_rx_sx_=$4
	local l_cntr_ix=$5
	local l_ctx_type="0x1b"
	
	if [ "$l_rx_sx_" -eq "1" ] ; then
		trns_type="RX"
		if [ "$l_port" -eq "0" ] ; then
			l_ctx_type="0x18"
		else
			l_ctx_type="0x1f"
		fi
	else
		trns_type="TX"
		if [ "$l_port" -eq "0" ] ; then
			l_ctx_type="0x36"
		else
			l_ctx_type="0x37"
		fi
	fi
	
	mcra $l_mst_dev $icmd_gvmi_addr        $l_gvmi
	mcra $l_mst_dev $icmd_ctx_type_addr    $l_ctx_type
	mcra $l_mst_dev $icmd_rw_addr	       0x1
	mcra $l_mst_dev $icmd_index_hi_addr    0x0
	mcra $l_mst_dev $icmd_index_lo_addr    $l_cntr_ix
	mcra $l_mst_dev $icmd_opcode_busy_addr 0x80010001
	sleep 0.5
	local busy=`mcra $l_mst_dev $icmd_busy_addr`
	while [ $(( busy )) -ne 0 ] ; do busy=`mcra $l_mst_dev $icmd_busy_addr`;  sleep 0.1 ; done
	
	local status=`mcra $l_mst_dev $icmd_status_addr`
	if [ "$status" != "0x00000000" ] ; then
	    echo  "ERROR: icmd failed, (status=$status);"
	    exit;
	fi
	
	local bytes_a=`mcra $l_mst_dev $(( icmd_start_addr))`
	local bytes_b=`mcra $l_mst_dev $(( icmd_start_addr + 4))`
	local bytes_c=$(((bytes_a << 32) + bytes_b))
	
	local packets_a=`mcra $l_mst_dev $(( icmd_start_addr + 8))`
	local packets_b=`mcra $l_mst_dev $(( icmd_start_addr + 8 + 4))`
	local packets_c=$(((packets_a << 32) + packets_b))

	case "$l_cntr_ix" in
		0)      cntr_string="DONT_CARE    " ;;
		1)      cntr_string="ERRORS       " ;;
		2)      cntr_string="IB_UNICAST   " ;;
		3)      cntr_string="IB_MUTICAST  " ;;
		4)      cntr_string="ETH_BROADCAST" ;;
		5)      cntr_string="ETH_UNICAST  " ;;
		6)      cntr_string="ETH_MULTICAST" ;;
		*)	cntr_string="FLOW_COUNTER " ;;
	esac

	if [ "$parsing" == "parsed" ] ; then
		printf "cntr[%d] %s - %14.35s : 0x%.16x  |  0x%.16x\n" $l_cntr_ix $trns_type $cntr_string $bytes_c $packets_c
	else
		printf "%.8x\n%.8x\n%.8x\n%.8x" $bytes_a $bytes_b $packets_a $packets_b
	fi

	for i in {0..3} ; do
		mcra $l_mst_dev $((icmd_start_addr + i*4)) 0x0
	done
}

###### read_res_icmd_and_print
# Read run icmd to read resourse and print the output
############
function read_res_icmd_and_print {
	local mst_dev=$1
	local gvmi=$2
	local res_type=$3
	local index=$4
	local port=$5
	local txt=""
	local i

	if [ "$action" == "counter" ]; then
		if [ "$tool" == "mft" ]; then
			txt=`resourcedump dump -d $mst_dev --segment FLOW_COUNTER --index1 $index`
			if [ "$parsing" == "parsed" ]; then
				txt=`echo "$txt" | awk '/Segment Type\: 0x1318/{nr[NR + 4];}; NR in nr' | sed 's/0x//g'`
				local p_a=`echo "$txt" | awk '/ /{print $1}'`
				local p_b=`echo "$txt" | awk '/ /{print $2}'`
				local p_c=$((( 16#$p_a << 32 ) + 16#$p_b ))
				local b_a=`echo "$txt" | awk '/ /{print $3}'`
				local b_b=`echo "$txt" | awk '/ /{print $4}'`
				local b_c=$((( 16#$b_a << 32 ) + 16#$b_b ))
				printf "Packets counter: 0x%x\n" $(( p_c ))
				printf "Octets counter: 0x%x\n" $(( b_c ))
			else
				resourcedump dump -d $mst_dev --segment FLOW_COUNTER --index1 $index
			fi
		else
			local icmd_start_addr="0x2000"
			for i in {0..15} ; do
				mcra $mst_dev $((icmd_start_addr + i*4)) 0x0
			done

			rx_counter=`get_gvmi_counter $mst_dev $port $gvmi 1 $index`
			sx_counter=`get_gvmi_counter $mst_dev $port $gvmi 0 $index`

			if [ "$parsing" == "parsed" ]; then
				rx_p=`echo $rx_counter | awk '{print $6}'`
				rx_b=`echo $rx_counter | awk '{print $8}'`
				sx_p=`echo $sx_counter | awk '{print $6}'`
				sx_b=`echo $sx_counter | awk '{print $8}'`
				total_p=`printf "0x%x" $(( rx_p + sx_p ))`
				total_b=`printf "0x%x" $(( rx_b + sx_b ))`
				echo "                           :     Packets        |      Bytes         "
				echo "-----------------------------------------------------------------------"
				echo $rx_counter
				echo "-----------------------------------------------------------------------"
				echo $sx_counter
				echo "-----------------------------------------------------------------------"
				printf "TOTAL                      : 0x%.16x | 0x%.16x\n" $total_p $total_b
				echo
			else
				echo $rx_counter
				echo $sx_counter
			fi
		fi
		exit
	fi

	if [ "$action" == "ste" ]; then
		txt=`resourcedump dump -d $mst_dev --segment STE_RANGE --index1 $index --num-of-obj1 1`
		txt=`echo "$txt" | awk '/Segment Type\: 0x1310/{nr[NR + 4]; nr[NR + 5]; nr[NR + 6]; nr[NR + 7];}; NR in nr' | sed 's/0x//g'`
		echo "$txt"
		if [ "$parsing" == "parsed" ]; then
			txt=`echo $txt | sed 's/ //g'`
			ste_parser $txt
		fi
		exit
	fi

	if [ "$action" == "rewrite" ] && [ "$tool" == "mft" ] ; then
		txt=`resourcedump dump -d $mst_dev --segment MDFY_HDR_RNG --index1 $index --num-of-obj1 1`
		if [ "$parsing" == "raw" ]; then
			txt=`echo "$txt" | awk '/Segment Type\: 0x1020/{nr[NR + 3]; nr[NR + 4]; nr[NR + 5]; nr[NR + 6]; nr[NR + 7]; nr[NR + 8]; nr[NR + 9]; nr[NR + 10]; nr[NR + 11];}; NR in nr' | sed 's/0x//g'`
		fi
		echo "$txt"
		exit
	fi

	if [ "$action" == "encap" ] && [ "$tool" == "mft" ] ; then
		if [ "$parsing" == "parsed" ]; then
			txt=`resourcedump dump -d $mst_dev --segment PKT_REFORMAT --index1 $index`
			txt=`echo "$txt" | awk '/Segment Type\: 0x1320/{nr[NR + 4]; nr[NR + 5]; nr[NR + 6]; nr[NR + 7]; nr[NR + 8]; nr[NR + 9]; nr[NR + 10]; nr[NR + 11];}; NR in nr' | sed 's/0x//g'`
			echo $txt
			exit
		else
			resourcedump dump -d $mst_dev --segment PKT_REFORMAT --index1 $index
		fi
		exit
	fi

	if [ "$action" == "pattern" ] && [ "$tool" == "mft" ] ; then
		resourcedump dump -d $mst_dev --segment MODIFY_PATTERN --index1 $index
		exit
	fi

	if [ "$action" == "argument" ] && [ "$tool" == "mft" ] ; then
		resourcedump dump -d $mst_dev --segment MODIFY_ARGUMENT --index1 $index
		exit
	fi

	if ["$action" == "aso_flow_hit" ] && [ "$tool" == "mft" ] ; then
		resourcedump dump -d $mst_dev --segment ASO_FLOW_HIT --index1 $index
		exit
	fi

	if ["$action" == "ft" ] && [ "$tool" == "mft" ] ; then
		resourcedump dump -d $mst_dev --segment QUERY_FT --index1 $index
		exit
	fi

	if ["$action" == "fte" ] && [ "$tool" == "mft" ] ; then
		resourcedump dump -d $mst_dev --segment QUERY_FTE --index1 $index
		exit
	fi

	if ["$action" == "fg" ] && [ "$tool" == "mft" ] ; then
		resourcedump dump -d $mst_dev --segment QUERY_FG --index1 $index
		exit
	fi

	if ["$action" == "qp" ] && [ "$tool" == "mft" ] ; then
		resourcedump dump -d $mst_dev --segment PRM_QUERY_QP --index1 $index
		exit
	fi

	if ["$action" == "cq" ] && [ "$tool" == "mft" ] ; then
		resourcedump dump -d $mst_dev --segment PRM_QUERY_CQ --index1 $index
		exit
	fi

	if ["$action" == "definer" ] && [ "$tool" == "mft" ] ; then
		resourcedump dump -d $mst_dev --segment HW_DEFINERS --index1 $index
		exit
	fi

	read_res_icmd $mst_dev $gvmi $res_type $(( index >> 1 ))

	if [ "$action" == "pattern" ] || [ "$action" == "argument" ] ; then
		for (( i=0; $((i*4)) < 64; i=$((i+1)) )) ; do
			res_val=`mcra $mst_dev $((0x2000 + i*4 ))`
			printf "%.8x " $res_val
			if [ $(( ( i % 4 ) )) -eq 3 ] ; then echo ; fi
		done > /tmp/read_res_type_form_icmd_$$

		cat /tmp/read_res_type_form_icmd_$$
	else
		for i in {0..32} ; do
			txt=`mcra $mst_dev $((0x2000 + (i*4) )) | sed 's/0x//'`
			echo "$txt"
		done
	fi

}


for arg in "$@"
do
	case "$arg" in
		-h)	echo ""
			echo "############## STE DUMPER ##################"
			echo
			echo "Disclaimer: this tool is for internal use for NVIDIA developers."
			echo "This tool is used to dump the steering data from the relevant device."
			echo "This tool will present raw data and has the ability to parse some of the data."
			echo
			echo "Usage:"
			echo "	./ste_dumper.sh -d <mst_dev> -g <gvmi> -i <index> <resource types> [--raw|-r] [--mft|--mcra] [-h] [--verbose|-v]"
			echo
			echo "Example:"
			echo "	Usage for dumping flow counter:"
			echo "		./ste_dumper.sh -d /dev/mst/mt4119_pciconf0 --counter  -i 104 -g 0 --mft"
			echo "	Usage for dumping STE:"
			echo "		/ste_dumper.sh -d /dev/mst/mt4119_pciconf0 --ste -i 0xe0000000 --raw"
			echo
			echo "Required flags:"
			echo "	-d <mst_dev> "
			echo "	-g <gvmi>"
			echo "	-i <index>"
			echo
			echo "Resource types:"
			echo "	--encap                   dump encap header"
			echo "	--rewrite                 dump header rewrite"
			echo "	--pattern                 dump pattern"
			echo "	--argument                dump argument"
			echo "	--counter                 dump counter"
			echo "	--ste                     dump ste"
			echo
			echo "Optional:"
			echo "	--mft       use commands just via mft tools"
			echo "	--mcra      use commands just via mcra interface"
			echo "	For --mft or --mcra if not specified will use automaticlly whats available"
			echo
			echo "	--raw | -r   print the raw data"
			echo
			echo "	--verbose | -v  output extra prints"
			echo
			echo "	-h output help"
			echo
			echo "##########################################"
			exit 1
			;;

		-i) p_arg=${arg##"-"} ;;
		-d) p_arg=${arg##"-"} ;;
		-g) p_arg=${arg##"-"} ;;
		--rewrite) action="rewrite" ;   res_type=0xe9  ;;
		--encap) action="encap" ;       res_type=0xb3  ;;
		--pattern) action="pattern" ;   res_type=0x73 ;;
		--argument) action="argument" ; res_type=0x72 ;;
		--counter) action="counter" ;	res_type=0x4fi ;;
		--ste) action="ste" ;		res_type=0x41  ;;
		--ft) action="ft" ;;
		--fte) action="fte" ;;
		--fg) action="fg" ;;
		--qp) action="qp" ;;
		--cq) action="cq" ;;
		--definer) action="definer" ;;
		--aso_flow_hit) action="aso_flow_hit" ;; 
		--mft) tool="mft" ;;
		--mcra) tool="mcra" ;;
		--raw|-r) parsing="raw" ;;
		--verbose|-v) verbosity="1";;
		 *) case $p_arg in
			i) index="$arg" ; p_arg=""  ;;
			d) mst_dev="$arg" ; p_arg=""  ;;
			g) gvmi="$arg" ; p_arg=""  ;;
			p) port="$arg" ; p_arg=""  ;;
			*) echo  ERROR: bad params $p_arg $arg; exit;;
			esac
	esac
done

index=`printf "%d" $index`

if [ "$mst_dev" == "-1" ] ; then 
	echo  "ERROR: missing mst_dev";
	exit 1;
else
	if [[ $mst_dev == *"4119"* || $mst_dev == *"4121"* || $mst_dev == *"41682"* ]]; then
		ste_version=0x0
	fi

	if [[ $mst_dev == *"4125"* || $mst_dev == *"41686"* ]]; then
		ste_version=0x1
	fi
fi

if [ "$gvmi" == "-1" ] ; then 
	echo  ERROR: missing gvmi;
	exit 1;
fi

if [ "$res_type" == "0" ] ; then 
	echo  ERROR: invalid res_type;
	exit 1;
fi

if [ "$index" == "-1" ] ; then 
	echo  ERROR: missing index;
	exit 1;
fi

if [ "$tool" == "mcra" ] && [ "$action" == "ste" ] ; then
        echo  ERROR: STE dumping is not supported via mcra;
        exit 1;
fi

if [[ "$tool" == "mft" && "$action" != "rewrite" && "$action" != "counter" && "$action" != "encap" ]] ; then
        echo  ERROR: $action dumping is not supported via mft;
        exit 1;
fi

if [[ "$action" != "counter" && "$action" != "ste" && "$action" != "encap" ]] ; then
	parsing="raw"
fi

if [ -x "$(command -v resourcedump)" ]; then
	res_dump_supp=1;
fi

if [ "$action" == "ste" ] && [ "$res_dump_supp" != "1" ] ; then
	echo  ERROR: STE parsing is not supported without resourcedump;
	exit 1;
fi 

index=`printf "0x%x" $index`
gvmi=`printf "0x%x" $gvmi`

if [ "$verbosity" != "0" ] ; then
	echo
	echo "##############################################################"
	echo "Read type: $res_type action: $action index: $index gvmi: $gvmi"
	echo "##############################################################"
fi

read_res_icmd_and_print $mst_dev $gvmi $res_type $index $port

exit

