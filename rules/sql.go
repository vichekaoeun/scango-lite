package rules

import (
    "fmt"
    "go/ast"
    "go/token"
    "strings"
)

var sqlKeywords = []string{
    "select", "insert", "update", "delete", "drop", "union", "from", "where",
}

func looksLikeSQL(s string) bool {
    s = strings.ToLower(s)
    for _, kw := range sqlKeywords {
        if strings.Contains(s, kw) {
            return true
        }
    }
    return false
}

func CheckSQLInjection(n ast.Node, fset *token.FileSet, filename string) {
    call, ok := n.(*ast.CallExpr)
    if !ok {
        return
    }

    // Get function name (e.g., db.Query, Exec, etc.)
    sel, ok := call.Fun.(*ast.SelectorExpr)
    if !ok {
        return
    }

    funcName := sel.Sel.Name
    if funcName != "Query" && funcName != "Exec" && funcName != "QueryRow" && funcName != "Prepare" {
        return
    }

    if len(call.Args) > 0 {
        // Handle literal or concatenation
        switch arg := call.Args[0].(type) {
        case *ast.BasicLit:
            if arg.Kind == token.STRING && looksLikeSQL(arg.Value) {
                pos := fset.Position(arg.Pos())
                fmt.Printf("%s:%d:%d: [WARNING] Possible SQL injection: raw query literal used in %s\n",
                    pos.Filename, pos.Line, pos.Column, funcName)
            }
        case *ast.BinaryExpr:
            pos := fset.Position(arg.Pos())
            fmt.Printf("%s:%d:%d: [WARNING] Possible SQL injection: string concatenation passed to %s\n",
                pos.Filename, pos.Line, pos.Column, funcName)
        case *ast.CallExpr:
            // e.g., fmt.Sprintf(...)
            if fun, ok := arg.Fun.(*ast.Ident); ok && fun.Name == "Sprintf" {
                pos := fset.Position(arg.Pos())
                fmt.Printf("%s:%d:%d: [WARNING] Possible SQL injection via fmt.Sprintf in %s\n",
                    pos.Filename, pos.Line, pos.Column, funcName)
            }
        }
    }
}
