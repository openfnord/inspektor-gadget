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

package trace

import (
	"encoding/json"
	"io"
	"os"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"

	commontrace "github.com/inspektor-gadget/inspektor-gadget/cmd/common/trace"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/trace"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
	beeTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bee/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	beeTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bee/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newBeeCmd() *cobra.Command {
	var commonFlags utils.CommonFlags
	var flags commontrace.BeeFlags

	runCmd := func(cmd *cobra.Command, args []string) error {
		localGadgetManager, err := localgadgetmanager.NewManager(commonFlags.RuntimeConfigs)
		if err != nil {
			return commonutils.WrapInErrManagerInit(err)
		}
		defer localGadgetManager.Close()

		parser, err := commonutils.NewGadgetParserWithRuntimeInfo(&commonFlags.OutputConfig, beeTypes.GetColumns())
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		networkEventCallback := func(container *containercollection.Container, event beeTypes.Event) {
			baseEvent := event.GetBaseEvent()
			if baseEvent.Type != eventtypes.NORMAL {
				commonutils.HandleSpecialEvent(baseEvent, commonFlags.Verbose)
				return
			}

			// Enrich with data from container
			if !container.HostNetwork {
				event.Namespace = container.Namespace
				event.Pod = container.Podname
				event.Container = container.Name
			}

			switch commonFlags.OutputMode {
			case commonutils.OutputModeJSON:
				b, err := json.Marshal(event)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s", fmt.Sprint(commonutils.WrapInErrMarshalOutput(err)))
					return
				}

				fmt.Println(string(b))
			case commonutils.OutputModeColumns:
				fallthrough
			case commonutils.OutputModeCustomColumns:
				fmt.Println(parser.TransformIntoColumns(&event))
			}
		}

		var progContent []byte
		if flags.File != "" {
			file, err := os.Open(flags.File)
			if err != nil {
				return err
			}
			defer file.Close()
			progContent, err = io.ReadAll(file)
			if err != nil {
				return commonutils.WrapInErrInvalidArg("file", err)
			}
		}

		beeGadget := &TraceGadget[beeTypes.Event]{
			commonFlags: &commonFlags,
			parser:      parser,
			createAndRunTracer: func(mountnsmap *ebpf.Map, enricher gadgets.DataEnricher, eventCallback func(beeTypes.Event)) (trace.Tracer, error) {
				beeTracerConfig := &beeTracer.Config{
					MountnsMap: mountnsmap,
					ProgLocation: flags.OCIImage,
					ProgContent: progContent,
				}
				tracer, err := beeTracer.NewTracer(beeTracerConfig, enricher, eventCallback)
				if err != nil {
					return nil, commonutils.WrapInErrGadgetTracerCreateAndRun(err)
				}

				selector := containercollection.ContainerSelector{
					Name: commonFlags.Containername,
				}

				config := &networktracer.ConnectToContainerCollectionConfig[beeTypes.Event]{
					Tracer:        tracer,
					Resolver:      &localGadgetManager.ContainerCollection,
					Selector:      selector,
					EventCallback: networkEventCallback,
					Base:          beeTypes.Base,
				}
				_, err = networktracer.ConnectToContainerCollection(config)
				if err != nil {
					return nil, fmt.Errorf("connecting tracer to container collection: %w", err)
				}

				return tracer, nil
			},
		}

		return beeGadget.Run()
	}

	cmd := commontrace.NewBeeCmd(runCmd, &flags)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}