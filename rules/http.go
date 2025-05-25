package rules

import (
    "fmt"
    "go/ast"
    "go/token"
    "strings"
)

func CheckInsecureHTTP(n ast.Node, fset *token.FileSet, filename string) {
    call, ok := n.(*ast.CallExpr)
    if !ok {
        return
    }

    // Check for HTTP-related function calls
    var funcName string
    var packageName string

    switch fun := call.Fun.(type) {
    case *ast.SelectorExpr:
        // http.Get, http.Post, client.Get, etc.
        if x, ok := fun.X.(*ast.Ident); ok {
            packageName = x.Name
            funcName = fun.Sel.Name
        }
    case *ast.Ident:
        // Direct function calls
        funcName = fun.Name
    default:
        return
    }

    // Check if it's an HTTP-related function
    httpFunctions := []string{"Get", "Post", "Put", "Delete", "Head", "Patch", "Do"}
    isHTTPFunc := false
    
    if packageName == "http" {
        for _, hf := range httpFunctions {
            if funcName == hf {
                isHTTPFunc = true
                break
            }
        }
    } else if strings.Contains(strings.ToLower(funcName), "http") {
        isHTTPFunc = true
    }

    if !isHTTPFunc {
        return
    }

    // Check arguments for insecure HTTP URLs
    for _, arg := range call.Args {
        switch argType := arg.(type) {
        case *ast.BasicLit:
            if argType.Kind == token.STRING && isInsecureURL(argType.Value) {
                pos := fset.Position(argType.Pos())
                fmt.Printf("%s:%d:%d: [WARNING] Insecure HTTP: using HTTP instead of HTTPS in %s\n", 
                    pos.Filename, pos.Line, pos.Column, funcName)
            }
        case *ast.BinaryExpr:
            // Check for URL concatenation that might result in HTTP
            if argType.Op == token.ADD && containsHTTPPattern(argType) {
                pos := fset.Position(argType.Pos())
                fmt.Printf("%s:%d:%d: [WARNING] Insecure HTTP: potential HTTP URL in concatenation for %s\n", 
                    pos.Filename, pos.Line, pos.Column, funcName)
            }
        case *ast.CallExpr:
            // Check fmt.Sprintf for HTTP URLs
            if fun, ok := argType.Fun.(*ast.SelectorExpr); ok {
                if x, ok := fun.X.(*ast.Ident); ok && x.Name == "fmt" && fun.Sel.Name == "Sprintf" {
                    if containsHTTPInSprintfArgs(argType) {
                        pos := fset.Position(argType.Pos())
                        fmt.Printf("%s:%d:%d: [WARNING] Insecure HTTP: potential HTTP URL in fmt.Sprintf for %s\n", 
                            pos.Filename, pos.Line, pos.Column, funcName)
                    }
                }
            }
        }
    }
}

func isInsecureURL(s string) bool {
    s = strings.ToLower(strings.Trim(s, `"`))
    return strings.HasPrefix(s, "http://")
}

func containsHTTPPattern(expr *ast.BinaryExpr) bool {
    return checkExprForHTTP(expr.X) || checkExprForHTTP(expr.Y)
}

func checkExprForHTTP(expr ast.Expr) bool {
    if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
        return isInsecureURL(lit.Value)
    }
    return false
}

func containsHTTPInSprintfArgs(call *ast.CallExpr) bool {
    for _, arg := range call.Args {
        if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
            if isInsecureURL(lit.Value) {
                return true
            }
        }
    }
    return false
}