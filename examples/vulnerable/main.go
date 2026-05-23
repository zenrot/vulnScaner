package main

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
)

const apiToken = "demo-hardcoded-token"

func main() {
	_ = md5.New()
	fmt.Println(rand.Int())
	_ = os.Chmod("secret.txt", 0777)
	_ = exec.Command("sh", "-c", "echo "+apiToken)
	_ = http.ListenAndServe(":8080", nil)
	_ = &tls.Config{InsecureSkipVerify: true}
}
