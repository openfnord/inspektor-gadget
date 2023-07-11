//go:build linux
// +build linux

// Copyright 2023 The Inspektor Gadget authors
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

package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// isHostNamespace checks if the current process is running in the specified host namespace
func isHostNamespace(nsKind string) (bool, error) {
	selfFileInfo, err := os.Stat("/proc/self/ns/" + nsKind)
	if err != nil {
		return false, err
	}
	selfStat, ok := selfFileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("reading inode of /proc/self/ns/%s", nsKind)
	}

	systemdFileInfo, err := os.Stat(fmt.Sprintf("%s/1/ns/%s", HostProcFs, nsKind))
	if err != nil {
		return false, err
	}
	systemdStat, ok := systemdFileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("reading inode of %s/1/ns/%s", HostProcFs, nsKind)
	}

	return selfStat.Ino == systemdStat.Ino, nil
}

// autoMount ensures that filesystems are mounted correctly.
// Some environments (e.g. minikube) runs with a read-only /sys without bpf
// https://github.com/kubernetes/minikube/blob/99a0c91459f17ad8c83c80fc37a9ded41e34370c/deploy/kicbase/entrypoint#L76-L81
// Docker Desktop with WSL2 also has filesystems unmounted.
func autoMount() error {
	fs := []struct {
		name  string
		path  string
		magic int64
	}{
		{
			"bpf",
			"/sys/fs/bpf",
			unix.BPF_FS_MAGIC,
		},
		{
			"debugfs",
			"/sys/kernel/debug",
			unix.DEBUGFS_MAGIC,
		},
		{
			"tracefs",
			"/sys/kernel/tracing",
			unix.TRACEFS_MAGIC,
		},
	}
	for _, f := range fs {
		var statfs unix.Statfs_t
		err := unix.Statfs(f.path, &statfs)
		if err != nil {
			return fmt.Errorf("statfs %s: %w", f.path, err)
		}
		if statfs.Type == f.magic {
			log.Debugf("%s already mounted", f.name)
			continue
		}
		err = unix.Mount("none", f.path, f.name, 0, "")
		if err != nil {
			return fmt.Errorf("mounting %s: %w", f.path, err)
		}
		log.Debugf("%s mounted (%s)", f.name, f.path)
	}
	return nil
}

// autoWindowsWorkaround overrides HostRoot and HostProcFs if necessary.
// Docker Desktop with WSL2 sets up host volumes with weird pidns.
func autoWindowsWorkaround() error {
	// If we're not in a container, we can't use this workaround
	if HostRoot == "/" {
		return nil
	}

	// If /host/proc is correctly set up, we don't need this workaround
	target, err := os.Readlink(HostProcFs + "/self")
	if target != "" && err == nil {
		return nil
	}

	log.Warnf("%s's pidns is neither the current pidns or a parent of the current pidns. Remounting.", HostProcFs)
	err = unix.Mount("/proc", HostProcFs, "", unix.MS_BIND, "")
	if err != nil {
		return fmt.Errorf("remounting %s: %w", HostProcFs, err)
	}
	// Find lifecycle-server process and set HOST_PID to its root
	processes, err := os.ReadDir(HostProcFs)
	if err != nil {
		return fmt.Errorf("reading %s: %w", HostProcFs, err)
	}
	for _, p := range processes {
		if !p.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}

		cmdLine := GetProcCmdline(pid)
		if cmdLine[0] != "/usr/bin/lifecycle-server" {
			continue
		}
		log.Debugf("Found lifecycle-server process %s", p.Name())

		buf, err := os.ReadFile(fmt.Sprintf("/proc/%s/cgroup", p.Name()))
		if err != nil {
			continue
		}
		if !strings.Contains(string(buf), "/podruntime/docker") {
			continue
		}
		log.Debugf("Found lifecycle-server process %s in cgroup /podruntime/docker", p.Name())

		HostRoot = fmt.Sprintf("/proc/%s/root/", p.Name())
		HostProcFs = filepath.Join(HostRoot, "/proc")
		log.Warnf("Overriding HostRoot=%s HostProcFs=%s (lifecycle-server)", HostRoot, HostProcFs)

		return nil
	}

	return errors.New("lifecycle-server process not found")
}
