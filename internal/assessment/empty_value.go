// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

func explicitlyEmptyValue(value any) bool {
	switch item := value.(type) {
	case nil:
		return true
	case string:
		return item == ""
	case bool:
		return !item
	case []any:
		return len(item) == 0
	case map[string]any:
		return len(item) == 0
	}
	return false
}
