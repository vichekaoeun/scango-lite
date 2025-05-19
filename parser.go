package main

import (
    "fmt"
    "go/parser"
    "go/token"
    "go/ast"
    "os"
    "path/filepath"
)

func ParseDirectory(dir string) {
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error))
	if err != nil{
		return err
	}

}