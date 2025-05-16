#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2025 NVIDIA CORPORATION. All rights reserved.

import time
import sys
import os

from src.dr_common import *
from src.dr_common_functions import import_library
from src.dr_db import _config_args

SSH_OPTIONS = "-q -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=no"

REMOTE_CMD_TIMEOUT = 30 * 60#wait maximum for 30 minutes

def remote_cmd(cmd, host, user, password, time_out=60):
    f = tempfile.mktemp()
    fout = open(f, 'w')

    cmd = "ssh %s@%s %s \"%s\"" % (user, host, SSH_OPTIONS, cmd)
    p = pexpect.spawnu(cmd, timeout=time_out)

    """
    Expect remote response asking for password
    """
    i = p.expect(['[Yy]es', 'YES', '[Pp]assword: '])
    if i < 2:
        p.sendline('YES')
        i = p.expect(['[Yy]es', 'YES', '[Pp]assword: '])
        if i < 2:
            p.sendline('Y')
            i = p.expect(['[Yy]es', 'YES', '[Pp]assword: '])
            if i < 2:
                print("Connection error")
                sys.exit(1)

    p.sendline(password)
    p.logfile = fout
    p.expect(pexpect.EOF)
    p.close()
    fout.close()

    fin = open(f, 'r')
    stdout = fin.read()
    fin.close()

    if p.exitstatus != 0:
        raise Exception(stdout)

    return stdout


def build_options():
    op = ""

    if _config_args.get("device") is not None:
        op += " -d %s " % (_config_args.get("device"))

    if _config_args.get("verbose") > 0:
        op += " -%s " % (_config_args.get("verbose") * "v")

    if _config_args.get("statistics") == True:
        op += " -s "

    if _config_args.get("args.extra_hw_res") != "":
        op += " --extra_hw_res %s " % _config_args.get("args.extra_hw_res")

    if _config_args.get("parse_hw_resources") == False:
        op += " --skip_parse "

    return op


def dr_connect_to_remote():
    if _config_args.get("remote_dep_lib") == False:
        globals()["pexpect"] = import_library("pexpect")
        globals()["tempfile"] = import_library("tempfile")
        globals()["getpass"] = import_library("getpass")
        _config_args["remote_dep_lib"] = True

    user_name = _config_args.get("user_name")
    raw_dump_file = _config_args.get("file_path")
    remote_ip = _config_args.get("remote_ip")
    options = build_options()
    remote_dump_file = "/tmp/dump_%s.csv" % (str(time.time()))
    dtrp = _config_args.get("dump_tool_remote_path")#dump tool remote path, "" if not provided

    password = getpass.getpass("Please enter %s@%s password:" % (user_name, remote_ip))
    _config_args["password"] = password

    print("connecting to remote...")

    if dtrp == "":
        #Check if mlx_steering_dump already exists in remote under /tmp/
        cmd = "ls /tmp/"
        out = remote_cmd(cmd, remote_ip, user_name, password, 15)

        dtrp = "/tmp/mlx_steering_dump"

        if "mlx_steering_dump" not in out.split("\n"):
            print("Copying mlx steering dump tool to remote")
            cmd = "mkdir -p /tmp/mlx_steering_dump/hws/src/"
            remote_cmd(cmd, remote_ip, user_name, password)

            #Copy current /src/*.py directory files
            cur_dir = os.path.dirname(os.path.abspath(__file__))
            cmd = "sshpass -p \"%s\" scp -o StrictHostKeyChecking=no \\%s/*.py %s@%s:/tmp/mlx_steering_dump/hws/src/." % \
                    (password, cur_dir, user_name, remote_ip)
            os.system(cmd)

            #Copy main script
            cmd = "sshpass -p \"%s\" scp -o StrictHostKeyChecking=no %s/../mlx_hw_steering_parser.py %s@%s:/tmp/mlx_steering_dump/hws/." % \
                    (password, cur_dir, user_name, remote_ip)
            os.system(cmd)

    #Copy app dump data file to remote
    cmd = "sshpass -p \"%s\" scp -o StrictHostKeyChecking=no  %s %s@%s:%s" % \
            (password, raw_dump_file, user_name, remote_ip, remote_dump_file)
    os.system(cmd)

    #Run dump tool in remote
    print("Runing HWS dump tool on remote...")
    print("Please wait, this may take some time...")
    cmd = "python3 %s/hws/mlx_hw_steering_parser.py -f %s %s" % \
            (dtrp, remote_dump_file, options)
    remote_cmd(cmd, remote_ip, user_name, password, REMOTE_CMD_TIMEOUT)

    print("HWS dump tool on remote finished")
    print("Copying parsed HWS dump file...")
    cmd = "sshpass -p \"%s\" scp -o StrictHostKeyChecking=no %s@%s:%s.parsed %s.parsed" % \
            (password, user_name, remote_ip, remote_dump_file, raw_dump_file)
    os.system(cmd)

    print(OUTPUT_FILE_STR + raw_dump_file)
    print(PARSED_OUTPUT_FILE_STR + ("%s.parsed" % raw_dump_file))

