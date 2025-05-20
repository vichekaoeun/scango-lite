package main

import(
	"fmt"
	"go/ast"
	"go/token"
	"strings"
)

func checkForSecrets(n ast.Node, fset *token.FileSet, filename string) { //takes the current ast node, fset gets line info and filename for context
	
}