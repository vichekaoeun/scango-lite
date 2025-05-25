package rules

import (
    "go/ast"
    "go/token"
    "strings"
    "cli/output"
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

func analyzeExprForSQL(expr ast.Expr, fset *token.FileSet, filename, funcName string) {
    switch val := expr.(type) {
    case *ast.BasicLit:
        if val.Kind == token.STRING && looksLikeSQL(val.Value) {
            pos := fset.Position(val.Pos())
            output.PrintSecurityIssue(pos.Filename, pos.Line, pos.Column, 
                "SQL injection", "raw SQL in " + funcName)
        }
    case *ast.BinaryExpr:
        pos := fset.Position(val.Pos())
        output.PrintSecurityIssue(pos.Filename, pos.Line, pos.Column,
            "SQL injection", "concatenated SQL in " + funcName)
    case *ast.CallExpr:
        if fun, ok := val.Fun.(*ast.Ident); ok && fun.Name == "Sprintf" {
            pos := fset.Position(val.Pos())
            output.PrintSecurityIssue(pos.Filename, pos.Line, pos.Column,
                "SQL injection", "fmt.Sprintf in " + funcName)
        }
    }
}

func CheckSQLInjection(n ast.Node, fset *token.FileSet, filename string) {
    // Check direct database calls
    if call, ok := n.(*ast.CallExpr); ok {
        sel, ok := call.Fun.(*ast.SelectorExpr)
        if !ok {
            return
        }

        funcName := sel.Sel.Name
        if funcName != "Query" && funcName != "Exec" && funcName != "QueryRow" && funcName != "Prepare" {
            return
        }

        if len(call.Args) > 0 {
            arg := call.Args[0]
            pos := fset.Position(arg.Pos())
            
            switch argType := arg.(type) {
            case *ast.BinaryExpr:
                if argType.Op == token.ADD {
                    output.PrintSecurityIssue(pos.Filename, pos.Line, pos.Column,
                        "SQL injection", "string concatenation in " + funcName)
                }
            case *ast.CallExpr:
                if fun, ok := argType.Fun.(*ast.SelectorExpr); ok {
                    if x, ok := fun.X.(*ast.Ident); ok && x.Name == "fmt" && fun.Sel.Name == "Sprintf" {
                        output.PrintSecurityIssue(pos.Filename, pos.Line, pos.Column,
                            "SQL injection", "fmt.Sprintf in " + funcName)
                    }
                }
            }
        }
        return
    }
    
    // Check variable assignments for SQL patterns
    if assign, ok := n.(*ast.AssignStmt); ok {
        for i, rhs := range assign.Rhs {
            if i < len(assign.Lhs) {
                if binExpr, ok := rhs.(*ast.BinaryExpr); ok && binExpr.Op == token.ADD {
                    if containsSQLPattern(binExpr) {
                        pos := fset.Position(binExpr.Pos())
                        output.PrintSecurityIssue(pos.Filename, pos.Line, pos.Column,
                            "SQL injection", "dangerous SQL string concatenation in assignment")
                    }
                }
            }
        }
    }
}

func checkExprForSQL(expr ast.Expr) bool {
    if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
        return looksLikeSQL(lit.Value)
    }
    return false
}

func containsSQLPattern(expr *ast.BinaryExpr) bool {
    // Check if either side contains SQL keywords
    return checkExprForSQL(expr.X) || checkExprForSQL(expr.Y)
}