package main

import(
	"fmt"
	"go/ast"
	"go/token"
	"strings"
)
//our list of suspicious names
//these are the names we will check against
var suspiciousNames = []string{
    "password", "pass", "apiKey", "secret", "token", "key", "auth", "credential",
}

func checkForSecrets(n ast.Node, fset *token.FileSet, filename string) { //takes the current ast node, fset gets line info and filename for context
	spec, ok := n.(*ast.ValueSpec);
	if ok{ //check if the node is a ValueSpec
		for i, name := range spec.Names{ //iterate over the variables in spec
			if isSuspicious(name.Name) && i < len(spec.Values){ //checks if the name is suspicious and exit if there are more values than variables names
				lit, ok := spec.Values[i].(*ast.BasicLit); //get the value of the variable
				if ok && lit.Kind == token.STRING{ //check if the value is a literal and is a string
					fmt.Printf("[WARNING] Hardcoded secret {%s} at %s\n", name.Name, fset.Position(lit.Pos()));
				}
			}
		}
	}

	assign, ok := n.(*ast.AssignStmt); //check if the node is an assignment statement
	if ok{
		for i, expr := range assign.Lhs{
			ident, ok := expr.(*ast.Ident);
			if ok{
				if isSuspicious(ident.Name) && i < len(assign.Rhs){
					lit, ok := assign.Rhs[i].(*ast.BasicLit); //get the value of the variable
					if ok && lit.Kind == token.STRING{ //check if the value is a literal and is a string
						fmt.Printf("[WARNING] Hardcoded secret {%s} at %s\n", ident.Name, fset.Position(lit.Pos()));
					}
				}
			}
		}
	}
}


func isSuspiciousName(name string) bool {
    name = strings.ToLower(name)
    for _, word := range suspiciousNames {
        if strings.Contains(name, word) {
            return true
        }
    }
    return false
}