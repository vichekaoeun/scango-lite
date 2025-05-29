package output

import (
    "fmt"
    "strings"
    "time" 
    "path/filepath" 
)

type ScanStats struct {
    StartTime     time.Time
    EndTime       time.Time
    FilesScanned  int
    LinesScanned  int64
    IssuesFound   int
    ScanDuration  time.Duration
    FilesPerSec   float64
    LinesPerSec   float64
}

var stats ScanStats

func StartScan() {
    stats.StartTime = time.Now()
    fmt.Println("\n🔍 scango-lite - Scanning for security issues...")
    fmt.Println(strings.Repeat("─", 50))
}

func IncrementFileCount() {
    stats.FilesScanned++
}

func AddLineCount(lines int) {
    stats.LinesScanned += int64(lines)
}

func EndScan() {
    stats.EndTime = time.Now()
    stats.ScanDuration = stats.EndTime.Sub(stats.StartTime)
    stats.FilesPerSec = float64(stats.FilesScanned) / stats.ScanDuration.Seconds()
    stats.LinesPerSec = float64(stats.LinesScanned) / stats.ScanDuration.Seconds()
}

func PrintPerformanceSummary() {
    EndScan()
    
    fmt.Println(strings.Repeat("─", 50))
    fmt.Printf("📊 Scan Results:\n")
    fmt.Printf("   Files scanned: %d\n", stats.FilesScanned)
    fmt.Printf("   Lines scanned: %d\n", stats.LinesScanned)
    fmt.Printf("   Issues found: %d\n\n", stats.IssuesFound)
    
    if stats.IssuesFound > 0 {
        fmt.Printf("Issues by type:\n")
        for issueType, count := range issueTypes {
            fmt.Printf("  • %s: %d\n", issueType, count)
        }
    }
    
    fmt.Printf("\n⚡ Performance:\n")
    fmt.Printf("   Scan time: %v\n", stats.ScanDuration.Round(time.Millisecond))
    fmt.Printf("   Files/sec: %.1f\n", stats.FilesPerSec)
    fmt.Printf("   Lines/sec: %.0f\n", stats.LinesPerSec)
    
    if stats.IssuesFound > 0 {
        fmt.Printf("\n❌ Security vulnerabilities detected!\n")
    } else {
        fmt.Printf("\n✅ No security issues found!\n")
    }
}

var (
    issueTypes = make(map[string]int)
)

func PrintSecurityIssue(filename string, line, column int, issueType, message string) {
    stats.IssuesFound++
    issueTypes[issueType]++
    
    var icon string
    switch {
    case strings.Contains(issueType, "SQL"):
        icon = "💉"
    case strings.Contains(issueType, "secret"):
        icon = "🔑" 
    case strings.Contains(issueType, "Command"):
        icon = "💻"
    case strings.Contains(issueType, "HTTP"):
        icon = "🔓"
    default:
        icon = "⚠️"
    }
    
    shortPath := filepath.Base(filepath.Dir(filename)) + "/" + filepath.Base(filename)
    fmt.Printf("%s %s:%d:%d - %s: %s\n", icon, shortPath, line, column, issueType, message)
}