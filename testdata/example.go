package main

import (
    "fmt"
    "os/exec"
    "database/sql"
)

func vulnerable(userInput string, db *sql.DB) {
    db.Query("SELECT * FROM users WHERE name = '" + userInput + "'")

    query := "SELECT * FROM users WHERE id = " + userInput

    db.Exec(fmt.Sprintf("DELETE FROM users WHERE name = '%s'", userInput))
}

func main() {
    password := "hunter2"
    var userID = "123"
    apiKey := "abc" + userID
    cfg := Config{
        Password: "hunter2",
        Token: "abc123",
    }
}
