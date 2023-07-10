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
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
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

// autoSdUnitRestart will automatically restart the process in a privileged
// systemd unit if the current process does not have enough capabilities.
func autoSdUnitRestart() (exit bool, err error) {
	const IgInSystemdUnitEnv = "IG_IN_SYSTEMD_UNIT"

	// No recursive restarts
	if os.Getenv(IgInSystemdUnitEnv) == "1" {
		return false, nil
	}

	// Only root can talk to the systemd socket
	if os.Geteuid() != 0 {
		return false, nil
	}

	// This workaround is meant for the "kubectl debug node" node. For now,
	// don't attempt it if we are obviously not running in that context.
	if HostRoot != "/host" || os.Getenv("KUBERNETES_PORT") == "" {
		return false, nil
	}

	// If we already have CAP_SYS_ADMIN, we don't need a workaround
	c, err := capability.NewPid2(0)
	if err != nil {
		return false, err
	}
	err = c.Load()
	if err != nil {
		return false, err
	}
	if c.Get(capability.EFFECTIVE, capability.CAP_SYS_ADMIN) {
		return false, nil
	}

	// if the host does not use systemd, we cannot use this workaround
	_, err = os.Stat("/host/run/systemd/private")
	if err != nil {
		return false, nil
	}

	// From here, we decided to use the workaround. This function will return
	// exit=true.
	runID := uuid.New().String()[:8]
	unitName := fmt.Sprintf("kubectl-debug-ig-%s.service", runID)
	log.Debugf("Missing capability. Starting systemd unit %q", unitName)

	// systemdDbus.NewSystemdConnectionContext() hard codes the path to the
	// systemd socket to /run/systemd/private. We need to make sure that this
	// path exists (if the /run:/run mount was set up correctly). If it doesn't
	// exist, we create the symlink to /host/run/systemd/private.
	_, err = os.Stat("/run/systemd/private")
	if errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll("/run/systemd", 0o755)
		if err != nil {
			return true, err
		}

		err = os.Symlink("/host/run/systemd/private", "/run/systemd/private")
		if err != nil {
			return true, fmt.Errorf("linking /run/systemd/private: %w", err)
		}
	} else if err != nil {
		return true, fmt.Errorf("statting /run/systemd/private: %w", err)
	}

	conn, err := systemdDbus.NewSystemdConnectionContext(context.TODO())
	if err != nil {
		return true, fmt.Errorf("connecting to systemd: %w", err)
	}
	defer conn.Close()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	statusChan := make(chan string, 1)
	cmd := []string{
		fmt.Sprintf("/proc/%d/root/usr/bin/ig", os.Getpid()),
	}
	cmd = append(cmd, os.Args[1:]...)
	envs := []string{IgInSystemdUnitEnv + "=1"}
	isTerminal := term.IsTerminal(int(os.Stdin.Fd())) || term.IsTerminal(int(os.Stdout.Fd())) || term.IsTerminal(int(os.Stderr.Fd()))
	if isTerminal && os.Getenv("TERM") != "" {
		envs = append(envs, "TERM="+os.Getenv("TERM"))
	}

	properties := []systemdDbus.Property{
		systemdDbus.PropDescription("Inspektor Gadget via kubectl debug"),
		// Type=oneshot ensures that StartTransientUnitContext will only return "done" when the job is done
		systemdDbus.PropType("oneshot"),
		// Pass stdio to the systemd unit
		{
			Name:  "StandardInputFileDescriptor",
			Value: dbus.MakeVariant(dbus.UnixFD(unix.Stdin)),
		},
		{
			Name:  "StandardOutputFileDescriptor",
			Value: dbus.MakeVariant(dbus.UnixFD(unix.Stdout)),
		},
		{
			Name:  "StandardErrorFileDescriptor",
			Value: dbus.MakeVariant(dbus.UnixFD(unix.Stderr)),
		},
		{
			Name:  "Environment",
			Value: dbus.MakeVariant(envs),
		},
		systemdDbus.PropExecStart(cmd, true),
	}

	_, err = conn.StartTransientUnitContext(context.TODO(),
		unitName, "fail", properties, statusChan)
	if err != nil {
		return true, fmt.Errorf("starting transient unit %q: %w", unitName, err)
	}

	select {
	case s := <-statusChan:
		log.Debugf("systemd unit %q returned %q", unitName, s)
		// "done" indicates successful execution of a job
		// See https://pkg.go.dev/github.com/coreos/go-systemd/v22/dbus#Conn.StartUnit
		if s != "done" {
			conn.ResetFailedUnitContext(context.TODO(), unitName)

			return true, fmt.Errorf("creating systemd unit `%s`: got `%s`", unitName, s)
		}
	case sig := <-signalChan:
		log.Debugf("%s: interrupt systemd unit %q", sig, unitName)
		statusStopChan := make(chan string, 1)
		_, err := conn.StopUnitContext(context.TODO(), unitName, "replace", statusStopChan)
		if err != nil {
			return true, fmt.Errorf("stopping transient unit %q: %w", unitName, err)
		}
		s := <-statusChan
		if s != "done" && s != "canceled" {
			return true, fmt.Errorf("stopping transient unit %q: got `%s`", unitName, s)
		}
	}

	return true, nil
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
