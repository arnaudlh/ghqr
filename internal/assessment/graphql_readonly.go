// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

func readOnlyGraphQL(raw []byte) bool {
	var body struct {
		Query         string          `json:"query"`
		Variables     json.RawMessage `json:"variables"`
		OperationName string          `json:"operationName"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return false
	}
	document, err := parser.ParseQuery(&ast.Source{Input: body.Query})
	if err != nil || len(document.Operations) != 1 {
		return false
	}
	operation := document.Operations[0]
	return operation.Operation == ast.Query && (body.OperationName == "" || body.OperationName == operation.Name)
}
