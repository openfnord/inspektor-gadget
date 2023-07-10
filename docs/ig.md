---
title: ig
weight: 80
description: >
  Description of the ig tool.
---

Inspektor Gadget relies on the Kubernetes API server to work. However, there are
[some cases](#use-cases) where it is necessary, or preferred, to trace
containers without passing through Kubernetes. In such scenarios, you can use
the `ig` tool, as it allows you to collect insights from the nodes to
debug your Kubernetes containers without relying on Kubernetes itself, but on
the container runtimes. It is important to remark that `ig` can also
be used to trace containers that were not created via Kubernetes.

Some characteristics of `ig`:
- It uses eBPF as its underlying core technology.
- Enriches the collected data with the Kubernetes metadata.
- Easy to install as it is a single binary (statically linked).

The architecture of `ig` is described in the main
[architecture](architecture.md#ig) document.

## Use cases

- In a Kubernetes environment, when the Kubernetes API server is not working
  properly, we cannot deploy Inspektor Gadget. Therefore, we still need a way to
  debug the containers of the cluster.
- In some cases, you might have root SSH access to the Kubernetes nodes of a
  cluster, but not to the `kubeconfig`.
- If you are implementing an application that needs to get insights from the
  Kubernetes node, you could include the `ig` binary in your container
  image, and your app simply execs it. In such a case, it is suggested to use
  the JSON output format to ease the parsing.
- Outside a Kubernetes environment, for observing and debugging standalone
  containers.

## Installation

The instruction to install `ig` are available in the main
[installation](install.md#installing-ig) guide.

## Usage

Currently, `ig` can trace containers managed by Docker regardless
of whether they were created via Kubernetes or not. In addition, it can also
use the CRI to trace containers managed by containerd and CRI-O, meaning only
the ones created via Kubernetes. Support for non-Kubernetes containers with
containerd is coming, see issue
[#734](https://github.com/inspektor-gadget/inspektor-gadget/issues/734).

By default, `ig` will try to communicate with the Docker Engine
API and the CRI API of containerd and CRI-O:

```bash
$ docker run -d --name myContainer nginx:1.21
95b814bb82b9e30dd935b03d04a7b00b6978ce018a6f55d6a9c7a824b31ec6b5

$ sudo ig list-containers
WARN[0000] Runtime enricher (cri-o): couldn't get current containers
RUNTIME       ID               NAME
containerd    7766d32caded4    calico-kube-controllers
containerd    2e3e4968b456f    calico-node
containerd    d3be7741b94ff    coredns
containerd    e7be3e4dc1bb4    coredns
containerd    fb4fe41921f30    etcd
containerd    136e7944d2077    kube-apiserver
containerd    ad8709a2c2ded    kube-controller-manager
containerd    66cf05654a47f    kube-proxy
containerd    a68bed42aa6b2    kube-scheduler
docker        95b814bb82b9e    myContainer
```

This output shows the containers `ig` retrieved from Docker and
containerd, while the warning message tells us that `ig` tried to
communicate with CRI-O but couldn't. In this case, it was because CRI-O was not
running in the system where we executed the test. However, it could also happen
if `ig` uses a different UNIX socket path to communicate with the
runtimes. To check which paths `ig` is using, you can use the `--help`
flag:

```bash
$ sudo ig list-containers --help
List all containers

Usage:
  ig list-containers [flags]

Flags:
  ...
      --containerd-socketpath string   containerd CRI Unix socket path (default "/run/containerd/containerd.sock")
      --crio-socketpath string         CRI-O CRI Unix socket path (default "/run/crio/crio.sock")
      --docker-socketpath string       Docker Engine API Unix socket path (default "/run/docker.sock")
  -r, --runtimes string                Container runtimes to be used separated by comma. Supported values are: docker, containerd, cri-o (default "docker,containerd,cri-o")
  -w, --watch                          After listing the containers, watch for new containers
  ...
```

If needed, we can also specify the runtimes to be used and their UNIX socket
path:

```bash
$ sudo ig list-containers --runtimes docker --docker-socketpath /some/path/docker.sock
RUNTIME    ID               NAME
docker     95b814bb82b9e    myContainer
```

### Common features

Notice that most of the commands support the following features even if, for
simplicity, they are not demonstrated in each command guide:

- JSON format and `custom-columns` output mode are supported through the
  `--output` flag.
- It is possible to filter events by container name using the `--containername`
  flag.
- It is possible to trace events from all the running processes, even though
  they were not generated from containers, using the `--host` flag.

For instance, for the `list-containers` command:

```bash
$ sudo ig list-containers -o json --containername etcd
[
  {
    "runtime": "containerd",
    "id": "fef9c7f66e0d68c554b7ea48cc3ef4e77c553957807de7f05ad0210a05d8c215",
    "pid": 1611,
    "mntns": 4026532270,
    "netns": 4026531992,
    "cgroupPath": "/sys/fs/cgroup/unified/system.slice/containerd.service",
    "cgroupID": 854,
    "cgroupV1": "/system.slice/containerd.service/kubepods-burstable-pod87a960e902bbb19289771a77e4b07353.slice:cri-containerd:fef9c7f66e0d68c554b7ea48cc3ef4e77c553957807de7f05ad0210a05d8c215",
    "cgroupV2": "/system.slice/containerd.service",
    "namespace": "kube-system",
    "podname": "etcd-master",
    "name": "etcd",
    "podUID": "87a960e902bbb19289771a77e4b07353"
  }
]
```

For example, with `--host`, you can get the following output:

```bash
$ sudo ig trace exec --host
CONTAINER                                               PID        PPID       COMM             RET ARGS

# Open another terminal.
$ cat /dev/null
$ docker run --name test-host --rm -t debian sh -c 'ls > /dev/null'
# Go back to first terminal.
CONTAINER                                               PID        PPID       COMM             RET ARGS
                               24640            4537             cat              0   /usr/bin/cat /dev/null
test-host                      24577            24553            sh               0   /bin/sh -c cat /dev/null
test-host                      24598            24577            cat              0   /bin/cat /dev/null
```

Events generated from containers have their container field set, while events which are generated from the host do not.

### Using ig with "kubectl debug node"

The "kubectl debug node" command is documented in
[Debugging Kubernetes Nodes With Kubectl](https://kubernetes.io/docs/tasks/debug/debug-cluster/kubectl-node-debug/).

Examples of commands:

```bash
$ kubectl debug node/minikube-docker -ti --image=ghcr.io/inspektor-gadget/ig -- ig --auto-sd-unit-restart=true trace exec
Creating debugging pod node-debugger-minikube-docker-c2wfw with container debugger on node minikube-docker.
If you don't see a command prompt, try pressing enter.
CONTAINER                                                     PID        PPID       COMM             RET ARGS
k8s_test01_test01_default_0aca2685-a8d2-49c7-9580-58fb806270… 1802638    1800551    cat              0   /bin/cat README
```

```bash
$ kubectl debug node/minikube-docker -ti --image=ghcr.io/inspektor-gadget/ig -- ig --auto-sd-unit-restart=true list-containers -o json
```

As of today, the `kubectl debug` command does not have a way to give enough privileges to the debugging pod to be able
to use `ig`.
This might change in the future: the Kubernetes Enhancement Proposal 1441
([KEP-1441](https://github.com/kubernetes/enhancements/tree/master/keps/sig-cli/1441-kubectl-debug))
suggests to implement Debugging Profiles (`--profile=`) to be able to give the necessary privileges.
kubectl v1.27 implements some of those profiles but not yet the "sysadmin" profile, so it is not possible to use
`--profile=` yet.

Meanwhile, `ig` provides the `--auto-sd-unit-restart` flag. The flag is `false` by default. When it is set to `true`,
`ig` will detect if it does not have enough privileges and it can transparently
re-execute itself in a privileged systemd unit if necessary.
This is possible because the "kubectl debug node" gives access to the systemd socket (`/run/systemd/private`) via the
/host volume.

### Using ig in a container

Example of command:

```bash
$ docker run -ti --rm \
    --privileged \
    -v /run:/run \
    -v /:/host \
    --pid=host \
    ghcr.io/inspektor-gadget/ig \
    trace exec
CONTAINER    PID        PPID       COMM  RET ARGS
cool_wright  1163565    1154511    ls    0   /bin/ls
```

List of flags:
- `--privileged` gives all capabilities such as `CAP_SYS_ADMIN`. It is required to run eBPF programs.
- `-v /run:/run` gives access to the container runtimes sockets (docker, containerd, CRI-O).
- `-v /:/host` gives access to the host filesystem. This is used to access the host processes via /host/proc, and access
  container runtime hooks (rootfs and config.json).
- `--pid=host` runs in the host PID namespace. Optional on Linux. This is necessary on Docker Desktop on Windows because
  /host/proc does not give access to the host processes.
