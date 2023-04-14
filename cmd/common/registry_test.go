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

package common

import (
	"fmt"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestHandleFileArguments(t *testing.T) {
	t.Parallel()

	testFlagSet := pflag.FlagSet{}
	var testFlagSetString string
	testFlagSet.StringVar(&testFlagSetString, "test", "", "test")

	testFlag := testFlagSet.Lookup("test")
	testFlag.Value.Set("@./test.file")

	handleFileArgument(testFlag)

	fmt.Println(testFlag.Value.String())
	expected := "eJwyNDIGBAAA//8BLQCX" // "123" zlib compressed and b64 coded
	assert.EqualValues(t, expected, testFlag.Value.String())
}