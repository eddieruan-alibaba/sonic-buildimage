#!/usr/bin/python3
import sys
import re
import json
import os

npsuite_dir = "/opt/cisco/silicon-one/npsuite/bin"
dsim_archive_dir = "/opt/cisco/silicon-one/res/dsim_archive"
dsim_config_file = "/usr/share/sonic/hwsku/nsim_config.json"

sys.path.append(npsuite_dir)
import nsim
import signal

MAX_VETH_PORT_NUM = 128

def parse_port_config_ini():
    try:
        fin = open("/usr/share/sonic/hwsku/port_config.ini", "rt")
    except:
        print("Failed to open port_config.ini")
        return []
    lines = fin.readlines()
    fin.close()
    titleline = lines.pop(0)
    if not re.match("#\s*name", titleline):
        print("port_config.ini file invalid format")
        return []
    tl = titleline[1:].strip().lower().split()
    lanes_index = tl.index("lanes")
    veths = []
    num = 1
    for line in lines:
        if num > MAX_VETH_PORT_NUM:
            break
        if not re.match("Ethernet\d+", line):
            continue
        fl = line.strip().split()
        if len(fl) != len(tl):
            print("tl {} fl {} invalid format".format(tl, fl))
            continue
        lanes = fl[lanes_index]
        if not re.match("\d(,\d){0,3}", lanes):
            continue
        lane = int(lanes.split(",")[0])
        slice = ((lane & 0xff00) >> 8) >> 1
        ifg = ((lane & 0xff00) >> 8) & 1
        pif = (lane & 0xff)
        print("lane {}: slice {} ifg {} pif {}".format(hex(lane), slice, ifg, pif))
        veths.append("-i")
        veths.append("{},{},{}@veth{}".format(slice, ifg, pif, num))
        num = num + 1
    return veths

#, "--disable-logger"
args=["--load-source-from-nsim-archive",dsim_archive_dir,
      "--device-path","/dev/testdev0",
      "--log-file-path","/var/log/", 
      "--log-level","3",
      "--log-file-max-size","100000000",
      "--log-file-max-files","3",
      "--num-of-threads","8",
      "--server","--host","127.0.0.1",
      "--enable-packet-dma",
      "--port","37561"]

# if nsim_config.json exists, use it. (G200)
# Otherwise, calculate it from port_config.ini. (Q200)
if os.path.exists(dsim_config_file):
    with open(dsim_config_file) as f:
        config = json.load(f)
        args.extend(["--revision", config["revision"]])
        for key, value in config["interfaces"].items():
            args.extend(["-i", "{}@{}".format(value, key)])
else:
    args.extend(parse_port_config_ini())
print("args {}".format(args))

print("Starting nsim main thread")
sys.stdout.flush()
nsim.main_wrapper(args)
device_handle=sys.nsim._device.get_connection_handle()
print(device_handle)
while True:
    signal.pause()
print("exiting nsim main thread")
sys.stdout.flush()
