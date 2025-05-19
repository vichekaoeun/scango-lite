package main

import "fmt"
import "os"

func printHelp() {
    fmt.Println(`gosec-lite - A lightweight static analyzer for Go security issues

Usage:
  go run main.go <command>

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
    fmt.Println("Scan complete.")
}

func main() {
    if len(os.Args) < 2{ //when user doesn't provide a command
        fmt.Println("Please provide a command, gosec-lite <command>")
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