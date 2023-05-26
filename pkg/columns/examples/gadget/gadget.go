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

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
)

type K8sMetadata struct {
	Node          string `column:"node"`
	PodName       string `column:"podName"`
	ContainerName string `column:"containerName"`
}

type RuntimeMetadata struct {
	RuntimeName   string `column:"runtimeName"`
	ContainerID   string `column:"containerID,width:13,maxWidth:64"`
	ContainerName string `column:"containerName"`
}

type GadgetData struct {
	K8sMetadata     `json:"k8sMetadata,inline" column:"k8s" columnTags:"kubernetes"`
	RuntimeMetadata `json:"runtimeMetadata,inline" column:"runtime" columnTags:"runtime"`
	GadgetData      string `json:"gadgetData" column:"gadgetData"`
}

var GadgetOutput = []*GadgetData{
	{
		K8sMetadata: K8sMetadata{
			Node:          "Node 1",
			ContainerName: "Container 1",
			PodName:       "Pod 1",
		},
		RuntimeMetadata: RuntimeMetadata{
			RuntimeName:   "Runtime 1",
			ContainerName: "Container 1",
			ContainerID:   "1",
		},
		GadgetData: "Data 1",
	},
	{
		K8sMetadata: K8sMetadata{
			Node:          "Node 2",
			ContainerName: "Container 2",
			PodName:       "Pod 2",
		},
		RuntimeMetadata: RuntimeMetadata{
			RuntimeName:   "Runtime 2",
			ContainerName: "Container 2",
			ContainerID:   "2",
		},
		GadgetData: "Data 2",
	},
	{
		K8sMetadata: K8sMetadata{
			Node:          "Node 3",
			ContainerName: "Container 3",
			PodName:       "Pod 3",
		},
		RuntimeMetadata: RuntimeMetadata{
			RuntimeName:   "Runtime 3",
			ContainerName: "Container 3",
			ContainerID:   "3",
		},
		GadgetData: "Data 3",
	},
}

// Defining the column helper here lets the program crash on start if there are
// errors in the syntax
var gadgetColumns = columns.MustCreateColumns[GadgetData]()

func main() {
	// Get columnMap
	cmap := gadgetColumns.GetColumnMap()

	// Get a new formatter and output all data
	formatter := textcolumns.NewFormatter(cmap)
	formatter.WriteTable(os.Stdout, GadgetOutput)

	/*
		NODE             CONTAINER        POD              RUNTIME          GADGETDATA
		————————————————————————————————————————————————————————————————————————————————————
		Node 1           Container 1      Pod 1            Runtime 1        Data 1
		Node 2           Container 2      Pod 2            Runtime 2        Data 2
		Node 3           Container 3      Pod 3            Runtime 3        Data 3
	*/

	fmt.Println()

	// Print JSON output
	b, _ := json.MarshalIndent(GadgetOutput, "", "  ")
	fmt.Println(string(b))

	fmt.Println()

	// Leave out kubernetes info for this one, but include gadget data (not-embedded struct) and runtime information
	formatter = textcolumns.NewFormatter(
		gadgetColumns.GetColumnMap(columns.Or(columns.WithEmbedded(false), columns.WithTag("runtime"))),
	)
	formatter.WriteTable(os.Stdout, GadgetOutput)

	/*
		RUNTIME          GADGETDATA
		—————————————————————————————————
		Runtime 1        Data 1
		Runtime 2        Data 2
		Runtime 3        Data 3
	*/
}
