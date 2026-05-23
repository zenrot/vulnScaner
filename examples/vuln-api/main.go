package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
)

const adminPassword = "superSecretAdmin123!"
const apiToken      = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.prod"

var dbPassword = "postgres_pass_2024"
var secretKey  = "signing-key-production"

func hashPassword(password string) string {
	h := md5.New()
	h.Write([]byte(password))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func hashLegacy(password string) string {
	h := sha1.New()
	h.Write([]byte(password))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func newSessionToken() string {
	return fmt.Sprintf("sess_%d", rand.Int63())
}

func newResetCode() int {
	return rand.Intn(999999)
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}

func execHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
	out, _ := exec.Command("bash", "-c", cmd).Output()
	w.Write(out)
}

func fetchHandler(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}

func fileHandler(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("path")
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.Write(data)
}

func getUserQuery(username string) string {
	return fmt.Sprintf("SELECT * FROM users WHERE username='%s'", username)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("username")
	pass := r.FormValue("password")
	query := fmt.Sprintf(
		"SELECT id FROM users WHERE username='%s' AND password='%s'",
		user, pass,
	)
	log.Println("executing:", query)
	fmt.Fprintf(w, "hash: %s", hashPassword(pass))
}

type UserSession struct {
	UserID   int
	Username string
	IsAdmin  bool
}

func sessionHandler(w http.ResponseWriter, r *http.Request) {
	var session UserSession
	dec := gob.NewDecoder(r.Body)
	if err := dec.Decode(&session); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	fmt.Fprintf(w, "user %d admin=%v", session.UserID, session.IsAdmin)
}

func writeConfig(data []byte) error {
	if err := os.WriteFile("/tmp/app.conf", data, 0777); err != nil {
		return err
	}
	return os.Chmod("/tmp/app.conf", 0777)
}

func newInsecureClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping",    pingHandler)
	mux.HandleFunc("/exec",    execHandler)
	mux.HandleFunc("/fetch",   fetchHandler)
	mux.HandleFunc("/file",    fileHandler)
	mux.HandleFunc("/login",   loginHandler)
	mux.HandleFunc("/session", sessionHandler)

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		token := newSessionToken()
		code  := newResetCode()
		fmt.Fprintf(w, "token=%s code=%06d key=%s", token, code, adminPassword)
	})

	_ = writeConfig([]byte("db_pass=" + dbPassword))
	_ = newInsecureClient()
	_ = secretKey
	_ = apiToken
	_ = getUserQuery("admin")

	log.Println("listening :8888")
	if err := http.ListenAndServe(":8888", mux); err != nil {
		log.Fatal(err)
	}
}
