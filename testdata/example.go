package main

import (
    "fmt"
    "os/exec"
)

func main() {
    fmt.Println("hello")
    exec.Command("ls", "-la")
}
