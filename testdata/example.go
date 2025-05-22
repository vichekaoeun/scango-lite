package main

import (
    "fmt"
    "os/exec"
)

func main() {
    password := "hunter2"
    var userID = "123"
    apiKey := "abc" + userID
    cfg := Config{
        Password: "hunter2",
        Token: "abc123",
    }
}
