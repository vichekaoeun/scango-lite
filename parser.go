package main

import (
    "fmt"
    "go/parser"
    "go/token"
    "go/ast"
    "os"
    "path/filepath"
    "strings"
    "github.com/vichekaoeun/scango-lite/rules"
    "github.com/vichekaoeun/scango-lite/output"
)

func parseFile(filename string) error {
    fset := token.NewFileSet() //create a token set for the file
    content, err := os.ReadFile(filename)
    if err != nil {
        return err
    }
    lineCount := strings.Count(string(content), "\n") + 1
    output.AddLineCount(lineCount)
    
    node, err := parser.ParseFile(fset, filename, nil, parser.AllErrors) // parser reads the file, parse the go code then return an AST node for that file
    if err != nil{
        return err //if there is an error parsing the file, return the error
    }

    ast.Inspect(node, func(n ast.Node) bool{
        rules.CheckForSecrets(n, fset, filename) //call the checkForSecrets function to check for secrets in the AST
        rules.CheckSQLInjection(n, fset, filename) //call the checkSQLInjection function to check for SQL injection in the AST
        rules.CheckCommandInjection(n, fset, filename)
        rules.CheckInsecureHTTP(n, fset, filename)
        return true //continue traversing the AST
    })
    return nil
}

func WalkFunc(path string, d os.DirEntry, err error) error {
    if err != nil {
        return err
    }

    // Skip vendor and other common directories
    if d.IsDir() {
        dirName := filepath.Base(path)
        if dirName == "vendor" || dirName == ".git" || dirName == "node_modules" {
            return filepath.SkipDir
        }
    }

    if !d.IsDir() && filepath.Ext(path) == ".go" { //checks if the file is a .go file
        fmt.Println("Parsing file:", path)
        output.IncrementFileCount() 
        err := parseFile(path) // calls parseFile function to parse the file
        if err != nil { //if there is an error parsing the file, print error
            fmt.Println("Error parsing file:", err)
        }
    }

    return nil
}

func ParseDirectory(dir string) error {
    return filepath.WalkDir(dir, WalkFunc)
}