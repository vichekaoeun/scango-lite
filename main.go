package main

import (
    "fmt"
    "os"
    "time"
    "github.com/vichekaoeun/scango-lite/output"
)

func printHelp() {
    fmt.Println(`scango-lite - A lightweight static analyzer for Go security issues

Usage:
  scango-lite <command>

Directory:
  cd into the directory you want scanned.

Available commands:
  run       Scan the current directory for .go files and insecure patterns
  bench     Run performance benchmark
  help      Show this help message`)
}

func scanCurrDir() {
    output.StartScan()
    
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
    output.PrintPerformanceSummary()
}

func runBenchmark(dir string) {
    fmt.Println("🏃 Running performance benchmark...")
    
    runs := 5
    var totalDuration time.Duration
    
    for i := 0; i < runs; i++ {
        fmt.Printf("Run %d/%d... ", i+1, runs)
        
        start := time.Now()
        ParseDirectory(dir)
        duration := time.Since(start)
        totalDuration += duration
        
        fmt.Printf("%.2fs\n", duration.Seconds())
    }
    
    avgDuration := totalDuration / time.Duration(runs)
    fmt.Printf("\n📈 Benchmark Results:\n")
    fmt.Printf("   Average scan time: %v\n", avgDuration.Round(time.Millisecond))
    fmt.Printf("   Fastest: %v\n", totalDuration.Round(time.Millisecond))
    fmt.Printf("   Total runs: %d\n", runs)
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
    case "bench":
        if len(os.Args) >= 3 {
            runBenchmark(os.Args[2])
        } else {
            runBenchmark(".")
        }
    case "help":
        printHelp()
    default:
        fmt.Println("Unknown command: ", command)  
    }
}