// Copyright 2019-2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package containerutils

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/containerd"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/crio"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/docker"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/podman"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

var AvailableRuntimes = []string{
	types.RuntimeNameDocker.String(),
	types.RuntimeNameContainerd.String(),
	types.RuntimeNameCrio.String(),
	types.RuntimeNamePodman.String(),
}

type RuntimeConfig struct {
	Name       types.RuntimeName
	SocketPath *string
}

func NewContainerRuntimeClient(runtime *RuntimeConfig) (runtimeclient.ContainerRuntimeClient, error) {
	switch runtime.Name {
	case types.RuntimeNameDocker:
		socketPath := runtime.SocketPath
		// If user did not modify the value by using --docker-socketpath, we will
		// use the env variable if set.
		// The same applies for other engines.
		if envsp := os.Getenv("INSPEKTOR_GADGET_DOCKER_SOCKETPATH"); envsp != "" && socketPath == nil {
			socketPath = &envsp
		}

		if socketPath == nil {
			return docker.NewDockerClient(runtimeclient.DockerDefaultSocketPath)
		}

		return docker.NewDockerClient(*socketPath)
	case types.RuntimeNameContainerd:
		socketPath := runtime.SocketPath
		if envsp := os.Getenv("INSPEKTOR_GADGET_CONTAINERD_SOCKETPATH"); envsp != "" && socketPath == nil {
			socketPath = &envsp
		}

		if socketPath == nil {
			return containerd.NewContainerdClient(runtimeclient.ContainerdDefaultSocketPath)
		}

		return containerd.NewContainerdClient(*socketPath)
	case types.RuntimeNameCrio:
		socketPath := runtime.SocketPath
		if envsp := os.Getenv("INSPEKTOR_GADGET_CRIO_SOCKETPATH"); envsp != "" && socketPath == nil {
			socketPath = &envsp
		}

		if socketPath == nil {
			return crio.NewCrioClient(runtimeclient.CrioDefaultSocketPath)
		}

		return crio.NewCrioClient(*socketPath)
	case types.RuntimeNamePodman:
		socketPath := runtime.SocketPath
		if envsp := os.Getenv("INSPEKTOR_GADGET_PODMAN_SOCKETPATH"); envsp != "" && socketPath == nil {
			socketPath = &envsp
		}

		if socketPath == nil {
			return podman.NewPodmanClient(runtimeclient.PodmanDefaultSocketPath), nil
		}

		return podman.NewPodmanClient(*socketPath), nil
	default:
		return nil, fmt.Errorf("unknown container runtime: %s (available %s)",
			runtime.Name, strings.Join(AvailableRuntimes, ", "))
	}
}

func getNamespaceInode(pid int, nsType string) (uint64, error) {
	fileinfo, err := os.Stat(filepath.Join(host.HostProcFs, fmt.Sprint(pid), "ns", nsType))
	if err != nil {
		return 0, err
	}
	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("not a syscall.Stat_t")
	}
	return stat.Ino, nil
}

func GetMntNs(pid int) (uint64, error) {
	return getNamespaceInode(pid, "mnt")
}

func GetNetNs(pid int) (uint64, error) {
	return getNamespaceInode(pid, "net")
}

func ParseOCIState(stateBuf []byte) (id string, pid int, err error) {
	ociState := &ocispec.State{}
	err = json.Unmarshal(stateBuf, ociState)
	if err != nil {
		// Some versions of runc produce an invalid json...
		// As a workaround, make it valid by trimming the invalid parts
		fix := regexp.MustCompile(`(?ms)^(.*),"annotations":.*$`)
		matches := fix.FindStringSubmatch(string(stateBuf))
		if len(matches) != 2 {
			err = fmt.Errorf("parsing OCI state: matches=%+v\n %w\n%s", matches, err, string(stateBuf))
			return
		}
		err = json.Unmarshal([]byte(matches[1]+"}"), ociState)
		if err != nil {
			err = fmt.Errorf("parsing OCI state: %w\n%s", err, string(stateBuf))
			return
		}
	}
	id = ociState.ID
	pid = ociState.Pid
	return
}
