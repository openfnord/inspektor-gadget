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

package containerhook

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
)

const (
	containerNamePrefix = "ch-test-container"
)

func TestContainerHook(t *testing.T) {
	t.Parallel()

	cb := func(event ContainerEvent) {
		t.Log(
			"Received event:",
			"Type", event.Type,
			"ID", event.ContainerID,
			"Name", event.ContainerName,
			"PID", event.ContainerPID,
		)
	}
	cn, err := NewContainerNotifier(cb)
	require.Nil(t, err)
	require.NotNil(t, cn)
	t.Cleanup(func() {
		cn.Close()
	})

	for _, runtime := range testutils.SupportedContainerRuntimes {
		t.Run(runtime.String(), func(t *testing.T) {
			runtime := runtime
			t.Parallel()

			cn := fmt.Sprintf("%s-%s", containerNamePrefix, runtime)

			// Run test container
			c, err := testutils.NewContainer(runtime, cn, "cat /dev/null")
			require.Nil(t, err)
			require.NotNil(t, c)
			c.Run(t)

			time.Sleep(2 * time.Second)
		})
	}
}
