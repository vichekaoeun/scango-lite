package main

import "fmt"
import "os"
import "github.com/vichekaoeun/scango-lite/output"

func printHelp() {
    fmt.Println(`scango-lite - A lightweight static analyzer for Go security issues

Usage:
  scango-lite <command>

Directory:
  cd into the directory you want scanned.

Available commands:
  run       Scan the current directory for .go files and insecure patterns
  help      Show this help message`)
}

func scanCurrDir() {
    dir, err := os.Getwd()
    if err != nil{
        fmt.Println("Error getting current directory:", err)
        return
    }
    err = ParseDirectory(dir) //parse the current directory
    if err != nil{
        fmt.Println("Error parsing directory:", err)
        return
    }
    output.PrintSummary()
}

func main() {
    if len(os.Args) < 2{ //when user doesn't provide a command
        fmt.Println("Please provide a command, scango-lite <command>")
        os.Exit(1)
    }
    command := os.Args[1] //capture command from 1st argument

    switch command{
    case "run":
        scanCurrDir()
    case "help":
        printHelp()
    default:
        fmt.Println("Unknown command: ", command)  
    }

}