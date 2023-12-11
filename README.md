# XACL - XDP Access Control List

based on (XDP Tutorial - Basic04)

## Usage

- Setup dependencies

```
sudo apt update
sudo apt install clang llvm libelf-dev libpcap-dev build-essential linux-headers-$(uname -r) linux-tools-common linux-tools-generic libc6-dev-i386 libxdp-dev xdp-tools
```

- Set your kernel version

```
vim ./xacl_core/common_kern_user.h
```

choose `#define KERNEL_5_10` when your kernel version between 5.10 - 5.17
or `#define KERNEL_5_17` when >= 5.17 (this will use `bpf_loop` and it supports higher amount of rules)

- Compile the project

```
./configure
make
```

- Attach XDP program to your interface

```
sudo ./xacl_core/xdp_loader -d **YOUR_DEV_NAME**
```

- Set rules to bpf map

```
sudo ./xlb_core/xacladm load **YOUR_DEV_NAME** **CONFIG_FILE_PATH**
```

(some example config rule files are in `./conf.d`)

The rules format is

```
saddr/mask daddr/mask sport dport proto action
```

such as (deny all request from 192.168.122.0/24 to access the SSH service)

```
192.168.122.0/24 0.0.0.0/0 0 22 TCP DENY
```

or (deny all PING request)
```
0.0.0.0/0 0.0.0.0/0 0 0 ICMP DENY
```

or (allow all request)
```
0.0.0.0/0 0.0.0.0/0 0 0 0 ALLOW
```

- Check if the rules are loaded in /sys/fs/bpf/**YOUR_DEV_NAME**

```
sudo cat /sys/fs/bpf/**YOUR_DEV_NAME**/rules_map_ipv4
```

- Check status collect

```
sudo ./xacl_core/xdp_stats -d **YOUR_DEV_NAME**
```

result:

```
Collecting stats from BPF map
 - BPF map (bpf_map_type:6) id:1720 name:xdp_stats_map key_size:4 value_size:16 max_entries:5
XDP-action  
XDP_ABORTED            0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250293
XDP_DROP               0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250259
XDP_PASS            1293 pkts (        20 pps)         144 Kbytes (     0 Mbits/s) period:0.250261
XDP_TX                 0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250263
XDP_REDIRECT           0 pkts (         0 pps)           0 Kbytes (     0 Mbits/s) period:0.250265
```



