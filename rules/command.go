package rules

import (
    "go/ast"
    "go/token"
    "strings"
    "cli/output"
)

func CheckCommandInjection(n ast.Node, fset *token.FileSet, filename string) {
    call, ok := n.(*ast.CallExpr)
    if !ok {
        return
    }

    // Check if it's exec.Command or exec.CommandContext
    sel, ok := call.Fun.(*ast.SelectorExpr)
    if !ok {
        return
    }

    // Check if it's from the exec package
    if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "exec" {
        return
    }

    funcName := sel.Sel.Name
    if funcName != "Command" && funcName != "CommandContext" {
        return
    }

    // Check arguments for potential injection
    if len(call.Args) == 0 {
        return
    }

    // Skip first arg if CommandContext (it's the context)
    startIdx := 0
    if funcName == "CommandContext" {
        startIdx = 1
    }

    if len(call.Args) <= startIdx {
        return
    }

    // Check for dangerous patterns
    for i := startIdx; i < len(call.Args); i++ {
        arg := call.Args[i]
        pos := fset.Position(arg.Pos())

        switch argType := arg.(type) {
        case *ast.BinaryExpr:
            // String concatenation - potentially dangerous
            if argType.Op == token.ADD {
                output.PrintSecurityIssue(pos.Filename, pos.Line, pos.Column, 
                    "Command injection", "string concatenation in exec." + funcName)
            }
        case *ast.CallExpr:
            // fmt.Sprintf - potentially dangerous
            if fun, ok := argType.Fun.(*ast.SelectorExpr); ok {
                if x, ok := fun.X.(*ast.Ident); ok && x.Name == "fmt" && fun.Sel.Name == "Sprintf" {
                    output.PrintSecurityIssue(pos.Filename, pos.Line, pos.Column, 
                        "Command injection", "fmt.Sprintf in exec." + funcName)
                }
            }
        case *ast.BasicLit:
            // Check for shell execution patterns
            if argType.Kind == token.STRING && containsShellPattern(argType.Value) {
                output.PrintSecurityIssue(pos.Filename, pos.Line, pos.Column, 
                    "Command injection", "shell execution in exec." + funcName)
            }
        }
    }
}

func containsShellPattern(s string) bool {
    s = strings.ToLower(s)
    shellPatterns := []string{"sh", "bash", "cmd", "/bin/sh", "/bin/bash", "cmd.exe"}
    
    for _, pattern := range shellPatterns {
        if strings.Contains(s, pattern) {
            return true
        }
    }
    return false
}