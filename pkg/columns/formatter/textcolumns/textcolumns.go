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

package textcolumns

import (
	"sort"
	"strings"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
)

type Column[T any] struct {
	col             *columns.Column[T]
	calculatedWidth int
	treatAsFixed    bool
	formatter       ColumnFormatter
}

type TextColumnsFormatter[T any] struct {
	options         *Options
	columns         map[string]*Column[T]
	currentMaxWidth int
	showColumns     []*Column[T]
	fillString      string
}

// NewFormatter returns a TextColumnsFormatter that will turn entries of type T into tables that can be shown
// on terminals or other frontends using fixed-width characters
func NewFormatter[T any](columns columns.ColumnMap[T], options ...Option) *TextColumnsFormatter[T] {
	opts := DefaultOptions()
	for _, o := range options {
		o(opts)
	}

	formatterColumnMap := make(map[string]*Column[T])
	for columnName, column := range columns {
		formatterColumnMap[columnName] = &Column[T]{
			col:             column,
			calculatedWidth: column.Width,
		}
	}

	tf := &TextColumnsFormatter[T]{
		options: opts,
		columns: formatterColumnMap,
	}

	for _, column := range tf.columns {
		tf.setFormatter(column)
	}

	tf.SetShowColumns(opts.DefaultColumns)

	return tf
}

// SetShowDefaultColumns resets the shown columns to those defined by default
func (tf *TextColumnsFormatter[T]) SetShowDefaultColumns() {
	if tf.options.DefaultColumns != nil {
		tf.SetShowColumns(tf.options.DefaultColumns)
		return
	}
	newColumns := make([]*Column[T], 0)
	for _, c := range tf.columns {
		if !c.col.Visible {
			continue
		}
		newColumns = append(newColumns, c)
	}

	// Sort using the default sort order
	sort.Slice(newColumns, func(i, j int) bool {
		return newColumns[i].col.Order < newColumns[j].col.Order
	})

	tf.showColumns = newColumns

	tf.rebuild()
}

// SetShowColumns takes a comma separated list of column names that will be displayed when using the output methods
func (tf *TextColumnsFormatter[T]) SetShowColumns(columns []string) {
	if columns == nil {
		tf.SetShowDefaultColumns()
		return
	}

	newColumns := make([]*Column[T], 0)
	for _, c := range columns {
		if column, ok := tf.columns[strings.ToLower(c)]; ok {
			newColumns = append(newColumns, column)
		}
	}
	tf.showColumns = newColumns

	tf.rebuild()
}

func (tf *TextColumnsFormatter[T]) rebuild() {
	tf.buildFillString()
	tf.currentMaxWidth = -1 // force recalculation
	tf.AdjustWidthsToScreen()
}
