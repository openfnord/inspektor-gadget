//go:build linux
// +build linux

// Copyright 2022 The Inspektor Gadget authors
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

package tracer

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/byob/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"golang.org/x/sync/errgroup"
)

//go:embed ebpf-testdata/http_bpfel.o
var testProgramHTTP []byte

//go:embed ebpf-testdata/dns_bpfel.o
var testProgramDNS []byte

func getProgContent(name string) []byte {
	switch name {
	case "http":
		return testProgramHTTP
	case "dns":
		return testProgramDNS
	default:
		return nil
	}
}

// func TestByobTracerCreate(t *testing.T) {
// 	t.Parallel()

// 	utilstest.RequireRoot(t)

// 	tracer := createTracer(t, &tracer.Config{ProgContent: getProgContent("http")}, nil, func(*types.Event) {})
// 	if tracer == nil {
// 		t.Fatal("Returned tracer was nil")
// 	}
// }

// func TestByobTracerStopIdempotent(t *testing.T) {
// 	t.Parallel()

// 	utilstest.RequireRoot(t)

// 	tracer := createTracer(t, &tracer.Config{ProgContent: getProgContent("http")}, nil, func(*types.Event) {})

// 	// Check that a double stop doesn't cause issues
// 	tracer.Stop()
// 	tracer.Stop()
// }

// type sockOpt struct {
// 	level int
// 	opt   int
// 	value int
// }

func TestByobTracer(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	type testDefinition struct {
		runnerConfigs []*utilstest.RunnerConfig

		getTracerConfig func() *Config

		generateEventFn func(runners []*utilstest.Runner) error

		validateEvent func(t *testing.T, runners []*utilstest.Runner, events []types.Event)
	}

	for name, test := range map[string]testDefinition{
		"conn": {
			runnerConfigs: []*utilstest.RunnerConfig{
				// two runners
				{HostNetwork: true}, // server
				{HostNetwork: true}, // client
			},
			getTracerConfig: func() *Config {
				return &Config{
					ProgContent: getProgContent("http"),
				}
			},
			generateEventFn: generateTCPEventFn(t, "127.0.0.1:8080"),
			validateEvent: func(t *testing.T, runners []*utilstest.Runner, events []types.Event) {
				fmt.Println(events)
				if len(events) != 2 {
					t.Fatalf("got %d events, expected %d", len(events), 2)
				}
				payload := func(mntnsid uint64, pktType int, tid int) string {
					return fmt.Sprintf(
						`{"af":2,"daddr_v4":"127.0.0.1","mount_ns_id":%d,`+
							`"pid":%d,"pkt_type":%d,"saddr_v4":"127.0.0.1",`+
							`"task":"tracer.test","tid":%d,"verb":"GET /test HTTP/"}`,
						mntnsid, os.Getpid(), pktType, tid,
					)
				}
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, extra string) *types.Event {
					return &types.Event{
						Event: eventtypes.Event{
							Type: eventtypes.NORMAL,
						},
						WithMountNsID: eventtypes.WithMountNsID{
							MountNsID: runners[1].Info.MountNsID,
						},
						Payload: payload(
							runners[1].Info.MountNsID,
							4, // 0 = PACKET_HOST, 4 = PACKET_OUTGOING
							runners[1].Info.Tid,
						),
					}
				})(t, runners[1].Info, "none", events)

				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, extra string) *types.Event {
					return &types.Event{
						Event: eventtypes.Event{
							Type: eventtypes.NORMAL,
						},
						WithMountNsID: eventtypes.WithMountNsID{
							MountNsID: runners[0].Info.MountNsID,
						},
						Payload: payload(
							runners[0].Info.MountNsID,
							0, // 0 = PACKET_HOST, 4 = PACKET_OUTGOING
							runners[0].Info.Tid,
						),
					}
				})(t, runners[0].Info, "none", events)
			},
		},
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			events := []types.Event{}
			eventCallback := func(event *types.Event) {
				t.Logf("event: %+v", event)
				events = append(events, *event)
			}

			runners := []*utilstest.Runner{}
			tids := []uint32{}
			for _, runnerConfig := range test.runnerConfigs {
				runner := utilstest.NewRunnerWithTest(t, runnerConfig)
				runners = append(runners, runner)
				tids = append(tids, uint32(runner.Info.Tid))
			}

			tr := createTracer(t, test.getTracerConfig(),
				tids,
				eventCallback,
			)

			defer tr.Close()
			if err := tr.installTracer(); err != nil {
				t.Errorf("installing tracer: %v", err)
			}
			go tr.run()

			for _, pid := range tids {
				err := tr.Attach(pid)
				if err != nil {
					t.Errorf("Error while attaching to pid %d: %v", pid, err)
				}
			}

			defer tr.Stop()

			test.generateEventFn(runners)

			// Give some time for the tracer to capture the events
			time.Sleep(200 * time.Millisecond)

			test.validateEvent(t, runners, events)
		})
	}
}

func createTracer(
	t *testing.T, config *Config, pids []uint32, callback func(*types.Event),
) *Tracer {
	t.Helper()

	gadgetDesc := GadgetDesc{}
	tracerGadget, err := gadgetDesc.NewInstance()
	if err != nil {
		t.Fatalf("Error creating tracer: %s", err)
	}

	tracerInstance, ok := tracerGadget.(*Tracer)
	if !ok {
		t.Fatalf("Error casting tracer: %s", err)
	}

	tracerInstance.SetEventHandler(callback)
	tracerInstance.config.ProgContent = config.ProgContent

	return tracerInstance
}

func generateTCPEventFn(t *testing.T, endpoint string) func(runners []*utilstest.Runner) error {
	return func(runners []*utilstest.Runner) error {
		serverRunner := runners[0]
		clientRunner := runners[1]

		// Server runner: listening on socket
		var ln net.Listener

		utilstest.RunWithRunner(t, serverRunner, func() error {
			var err error
			ln, err = net.Listen("tcp", endpoint)
			if err != nil {
				return err
			}
			return err
		})

		// Connecting and accepting in parallel
		errs, _ := errgroup.WithContext(context.TODO())
		errs.Go(func() error {
			// Client runner: listening on socket
			utilstest.RunWithRunner(t, clientRunner, func() error {
				conn, err := net.Dial("tcp", endpoint)
				if err != nil {
					return err
				}
				fmt.Fprintf(conn, "GET /test HTTP/1.1\n\n")
				response, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					return err
				}
				if response != "Hello test!\n" {
					return fmt.Errorf("invalid response: %q", response)
				}
				conn.Close()
				return nil
			})
			return nil
		})
		errs.Go(func() error {
			// Server runner: accepting new connection socket
			utilstest.RunWithRunner(t, serverRunner, func() error {
				conn, err := ln.Accept()
				if err != nil {
					return err
				}
				message, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					return err
				}
				if !strings.HasPrefix(message, "GET /test") {
					return fmt.Errorf("invalid message: %q", message)
				}
				fmt.Fprintf(conn, "Hello test!\n")
				conn.Close()
				return nil
			})
			return nil
		})
		if err := errs.Wait(); err != nil {
			t.Fatalf("failed generating events: %s", err)
		}

		return nil
	}
}
