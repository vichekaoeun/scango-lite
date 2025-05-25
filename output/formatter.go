// In output/formatter.go
package output

import (
    "fmt"
    "path/filepath"
    "strings"
)

var (
    issueCount = 0
    fileCount  = 0
    issueTypes = make(map[string]int)
)

func PrintHeader() {
    fmt.Println("\n🔍 gosec-lite - Scanning for security issues...")
    fmt.Println(strings.Repeat("─", 50))
}

func IncrementFileCount() {
    fileCount++
}

func PrintSecurityIssue(filename string, line, column int, issueType, message string) {
    issueCount++
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
    fmt.Printf("%s %s:%d:%d - %s\n", icon, shortPath, line, column, message)
}

func PrintSummary() {
    fmt.Println(strings.Repeat("─", 50))
    fmt.Printf("📊 Scan complete: %d files, %d issues found\n", fileCount, issueCount)
    
    if issueCount > 0 {
        fmt.Println("\nIssues by type:")
        for issueType, count := range issueTypes {
            fmt.Printf("  • %s: %d\n", issueType, count)
        }
        fmt.Println("\n❌ Security vulnerabilities detected!")
    } else {
        fmt.Println("\n✅ No security issues found!")
    }
}