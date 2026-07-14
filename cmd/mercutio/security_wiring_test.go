package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestEveryOperatorMutationUsesCSRFBoundary(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Mount" {
			return true
		}
		pattern, ok := call.Args[0].(*ast.BasicLit)
		if !ok || pattern.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(pattern.Value)
		if err != nil || !strings.HasPrefix(value, "POST ") || !(strings.HasPrefix(value, "POST /api/cells") || strings.HasPrefix(value, "POST /gosx/action/")) {
			return true
		}
		checked++
		boundary, ok := call.Args[1].(*ast.CallExpr)
		if !ok {
			t.Errorf("%s is not mounted through operatorMutation", value)
			return true
		}
		identifier, named := boundary.Fun.(*ast.Ident)
		if !named || identifier.Name != "operatorMutation" {
			t.Errorf("%s is not mounted through operatorMutation", value)
		}
		return true
	})
	if checked < 10 {
		t.Fatalf("checked only %d operator mutation routes", checked)
	}
}
