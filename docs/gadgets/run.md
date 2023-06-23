---
title: 'Using run'
weight: 20
description: >
  The run command allows to create an instance of a gadget.
---

> ⚠️ This command is experimental and could change without prior notification. Only few gadgets are supported and we're working to extend this support.

The `run` gadget launches a gadget. Currently only local gadgets are supported and must be specified by using the following flags:
- `--prog`: Compiled eBPF object.
- `--definition`: Yaml file indicating the output format of the gadget.

The [gadgets](../../gadgets) folder include some sample gadgets to be used with this command.

## On Kubernetes

```bash
$ kubectl gadget run --prog @./gadgets/trace_tcpconnect_x86.bpf.o --definition @./gadgets/trace_tcpconnect.yaml
NODE                   NAMESPACE              POD                    CONTAINER              V… SRC          DST         DPORT SPORT UID      GID       PID
ubuntu-hirsute         default                mypod5                 mypod5                 4  172.16.118.1 1.1.1.1     80    37322 0        0         46104
ubuntu-hirsute         default                mypod5                 mypod5                 4  172.16.118.1 1.1.1.1     443   51306 0        0         46104

$ kubectl gadget run --prog @./gadgets/trace_open_x86.bpf.o --definition @./gadgets/trace_open.yaml
NODE             NAMESPACE        POD              CONTAINER        PID     GID      R… F… COMM     MNTNS_ID                 FNAME                    UID
ubuntu-hirsute   default          mypod5           mypod5           39901   0        3  59 sh      4026533267               .                       0
ubuntu-hirsute   default          mypod5           mypod5           39901   0        3  59 sh      4026533267               /                       0
ubuntu-hirsute   default          mypod5           mypod5           39901   0        3  10 sh      4026533267               /root/.ash_history      0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /etc/ld.so.cache        0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/x86_64-linux-gnu/tl 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/x86_64-linux-gnu/tl 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/x86_64-linux-gnu/tl 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/x86_64-linux-gnu/tl 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/x86_64-linux-gnu/x8 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/x86_64-linux-gnu/x8 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/x86_64-linux-gnu/x8 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/x86_64-linux-gnu/li 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /usr/lib/x86_64-linux-gn 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /usr/lib/x86_64-linux-gn 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /usr/lib/x86_64-linux-gn 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /usr/lib/x86_64-linux-gn 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /usr/lib/x86_64-linux-gn 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /usr/lib/x86_64-linux-gn 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /usr/lib/x86_64-linux-gn 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /usr/lib/x86_64-linux-gn 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/tls/x86_64/x86_64/l 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/tls/x86_64/libm.so. 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/tls/x86_64/libm.so. 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/tls/libm.so.6      0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/x86_64/x86_64/libm. 0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/x86_64/libm.so.6   0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        -2 52 cat     4026533267               /lib/x86_64/libm.so.6   0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        3  52 cat     4026533267               /lib/libm.so.6          0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        3  52 cat     4026533267               /lib/libresolv.so.2     0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        3  52 cat     4026533267               /lib/libc.so.6          0
ubuntu-hirsute   default          mypod5           mypod5           48328   0        3  0  cat     4026533267               /dev/null               0
```

## With `ig`

``` bash
$ sudo ig run --prog @./gadgets/trace_tcpconnect_x86.bpf.o --definition @./gadgets/trace_tcpconnect.yaml
CONTAINER                                                V… SRC                           DST                           DPORT SPORT UID      GID       PID
mycontainer3                                             4  172.17.0.5                    1.1.1.1                       80    43084 0        0         734228
mycontainer3                                             4  172.17.0.5                    1.1.1.1                       443   44342 0        0         734228

$ sudo ig run --prog @./gadgets/trace_open_x86.bpf.o --definition @./gadgets/trace_open.yaml
CONTAINER                        PID     GID      RET    FLAGS  COMM              MNTNS_ID                          FNAME                             UID
mycontainer3                     647342  0        3      591872 sh               4026533468                        /                                0
mycontainer3                     647342  0        3      1089   sh               4026533468                        /root/.ash_history               0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /etc/ld.so.cache                 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/x86_64-linux-gnu/tls/x86_64/ 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/x86_64-linux-gnu/tls/x86_64/ 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/x86_64-linux-gnu/tls/x86_64/ 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/x86_64-linux-gnu/tls/libm.so 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/x86_64-linux-gnu/x86_64/x86_ 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/x86_64-linux-gnu/x86_64/libm 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/x86_64-linux-gnu/x86_64/libm 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/x86_64-linux-gnu/libm.so.6  0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /usr/lib/x86_64-linux-gnu/tls/x86 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /usr/lib/x86_64-linux-gnu/tls/x86 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /usr/lib/x86_64-linux-gnu/tls/x86 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /usr/lib/x86_64-linux-gnu/tls/lib 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /usr/lib/x86_64-linux-gnu/x86_64/ 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /usr/lib/x86_64-linux-gnu/x86_64/ 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /usr/lib/x86_64-linux-gnu/x86_64/ 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /usr/lib/x86_64-linux-gnu/libm.so 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/tls/x86_64/x86_64/libm.so.6 0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/tls/x86_64/libm.so.6        0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/tls/x86_64/libm.so.6        0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/tls/libm.so.6               0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/x86_64/x86_64/libm.so.6     0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/x86_64/libm.so.6            0
mycontainer3                     734827  0        -2     524288 cat              4026533468                        /lib/x86_64/libm.so.6            0
mycontainer3                     734827  0        3      524288 cat              4026533468                        /lib/libm.so.6                   0
mycontainer3                     734827  0        3      524288 cat              4026533468                        /lib/libresolv.so.2              0
mycontainer3                     734827  0        3      524288 cat              4026533468                        /lib/libc.so.6                   0
mycontainer3                     734827  0        -2     0      cat              4026533468                        /dev/nulll                       0
```
