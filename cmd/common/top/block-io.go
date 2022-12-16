// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this block-io except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package top

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
)

func NewBlockIOCmd(runCmd func(*cobra.Command, []string) error) *cobra.Command {
	return &cobra.Command{
		Use:   fmt.Sprintf("block-io [interval=%d]", top.IntervalDefault),
		Short: "Periodically report block device I/O activity",
		RunE:  runCmd,
	}
}
