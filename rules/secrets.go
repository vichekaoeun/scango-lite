package rules

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

func CheckForSecrets(n ast.Node, fset *token.FileSet, filename string) { //takes the current ast node, fset gets line info and filename for context
	spec, ok := n.(*ast.ValueSpec);
	if ok{ //check if the node is a ValueSpec
		for i, name := range spec.Names{ //iterate over the variables in spec
			if isSuspiciousName(name.Name) && i < len(spec.Values){ //checks if the name is suspicious and exit if there are more values than variables names
				if lit, ok := spec.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					fmt.Printf("%s:%d:%d: [WARNING] Hardcoded secret {%s}\n",
						filename,
						fset.Position(lit.Pos()).Line,
						fset.Position(lit.Pos()).Column,
						name.Name)
				} else if bin, ok := spec.Values[i].(*ast.BinaryExpr); ok && bin.Op == token.ADD {
					if isStringLiteral(bin.X) || isStringLiteral(bin.Y) {
						pos := fset.Position(bin.Pos())
						fmt.Printf("%s:%d:%d: [WARNING] Suspicious string concat in {%s}\n", pos.Filename, pos.Line, pos.Column, name.Name)
					}
				}
			}
		}
	}

	assign, ok := n.(*ast.AssignStmt); //check if the node is an assignment statement
	if ok{
		for i, expr := range assign.Lhs{ //left-hand side assignment check, which includes multi-assignment
			ident, ok := expr.(*ast.Ident);
			if ok{
				if isSuspiciousName(ident.Name) && i < len(assign.Rhs){
                    // First: check for string literal
					if lit, ok := assign.Rhs[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						fmt.Printf("%s:%d:%d: [WARNING] Hardcoded secret {%s}\n",
							filename,
							fset.Position(lit.Pos()).Line,
							fset.Position(lit.Pos()).Column,
							ident.Name)
					} else if bin, ok := assign.Rhs[i].(*ast.BinaryExpr); ok && bin.Op == token.ADD {
						// Second: check for string concatenation
						if isStringLiteral(bin.X) || isStringLiteral(bin.Y) {
							fmt.Printf("[WARNING] Suspicious string concat in {%s} at %s\n", ident.Name, fset.Position(bin.Pos()))
						}
					}
				}
			}
		}
	}

	checkStructLiteral(n, fset, filename)
}


func isSuspiciousName(name string) bool { //compare the name with the suspicious names
    name = strings.ToLower(name)
    for _, word := range suspiciousNames {
        if strings.Contains(name, word) {
            return true
        }
    }
    return false
}

func isStringLiteral(expr ast.Expr) bool{
	lit, ok := expr.(*ast.BasicLit); //check if the expression is a basic literal
	return ok && lit.Kind == token.STRING //check if the literal is a string
}

func checkStructLiteral(n ast.Node, fset *token.FileSet, filename string) {
    compLit, ok := n.(*ast.CompositeLit)
    if !ok {
        return
    }

    for _, elt := range compLit.Elts {
        kv, ok := elt.(*ast.KeyValueExpr)
        if !ok {
            continue
        }

        keyIdent, ok := kv.Key.(*ast.Ident)
        if !ok {
            continue
        }

        if isSuspiciousName(keyIdent.Name) {
            if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
                pos := fset.Position(lit.Pos())
				fmt.Printf("%s:%d:%d: [WARNING] Hardcoded secret field {%s}\n", pos.Filename, pos.Line, pos.Column, keyIdent.Name)
            }
        }
    }
}