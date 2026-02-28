// test.go
package main

import (
    "os/exec"
    "crypto/md5"
    "html/template"
)

func main() {
    // VULNERABILITY GO001
    cmd := exec.Command("bash", "-c", "echo vulnerable")

    // VULNERABILITY GO002
    hash := md5.New()

    // VULNERABILITY GO003
    t, _ := template.New("foo").Parse(`<div>Hello</div>`)
}
