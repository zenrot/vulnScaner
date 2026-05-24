package scanner

type MatchType string

const (
	MatchCall                MatchType = "call"
	MatchCallPkg             MatchType = "call_pkg"
	MatchCallShell           MatchType = "call_shell"
	MatchCallPermissiveChmod MatchType = "call_permissive_chmod"
	MatchCompositeFieldBool  MatchType = "composite_field_bool"
	MatchSecretValue         MatchType = "secret_value"
	MatchImport              MatchType = "import"
)

type RuleMatch struct {
	Type         MatchType
	Functions    []string
	Package      string
	Packages     []string
	TypeSelector string
	Field        string
	BoolValue    bool
	NamePatterns []string
	MinLength    int
}

type Rule struct {
	ID          string
	Title       string
	Severity    Severity
	Why         string
	Remediation string
	Match       RuleMatch
	Fixture     string
}

var BuiltinRules = []Rule{
	{
		ID:          "GO-HARDCODED-SECRET",
		Title:       "Hardcoded secret-like value",
		Severity:    SeverityHigh,
		Why:         "Secrets committed to source control are difficult to rotate and can be recovered from history.",
		Remediation: "Load secrets from a secret manager, environment, or runtime configuration outside version control.",
		Match: RuleMatch{
			Type: MatchSecretValue,
			NamePatterns: []string{
				"password", "passwd", "secret", "token", "apikey", "api_key",
				"privatekey", "private_key", "credential", "credentials",
				"passphrase", "authkey", "auth_key",
			},
			MinLength: 16,
		},
		Fixture: `package main

const apiToken = "hardcoded-token-value-1234"
`,
	},
	{
		ID:          "GO-CRYPTO-WEAK",
		Title:       "Weak cryptographic primitive",
		Severity:    SeverityHigh,
		Why:         "Weak or broken cryptographic primitives enable collision, downgrade, or confidentiality attacks.",
		Remediation: "Use SHA-256/SHA-512 for hashing or AES-GCM/ChaCha20-Poly1305 for encryption.",
		Match: RuleMatch{
			Type: MatchCall,
			Functions: []string{
				"crypto/md5.New", "crypto/md5.Sum",
				"crypto/sha1.New", "crypto/sha1.Sum",
				"crypto/des.NewCipher", "crypto/des.NewTripleDESCipher",
				"crypto/rc4.NewCipher",
			},
		},
		Fixture: `package main

import "crypto/md5"

func f() { md5.New() }
`,
	},
	{
		ID:          "GO-RAND-INSECURE",
		Title:       "Insecure random source (math/rand)",
		Severity:    SeverityMedium,
		Why:         "math/rand is deterministic and predictable; unsuitable for tokens, secrets, nonces, or security decisions.",
		Remediation: "Use crypto/rand for security-sensitive randomness.",
		Match: RuleMatch{
			Type:    MatchCallPkg,
			Package: "math/rand",
		},
		Fixture: `package main

import "math/rand"

func f() { rand.Int() }
`,
	},
	{
		ID:          "GO-HTTP-NO-TLS",
		Title:       "HTTP server without TLS",
		Severity:    SeverityMedium,
		Why:         "Plain HTTP exposes credentials, session tokens, and sensitive data in transit.",
		Remediation: "Use ListenAndServeTLS or terminate TLS at a trusted proxy.",
		Match: RuleMatch{
			Type:      MatchCall,
			Functions: []string{"net/http.ListenAndServe"},
		},
		Fixture: `package main

import "net/http"

func f() { http.ListenAndServe(":8080", nil) }
`,
	},
	{
		ID:          "GO-CMD-SHELL",
		Title:       "Shell command execution",
		Severity:    SeverityHigh,
		Why:         "Passing dynamic data through a shell creates command injection risk.",
		Remediation: "Call the target executable directly with structured arguments; validate all external inputs.",
		Match:       RuleMatch{Type: MatchCallShell},
		Fixture: `package main

import "os/exec"

func f() { exec.Command("sh", "-c", "echo") }
`,
	},
	{
		ID:          "GO-FILE-PERMISSIVE",
		Title:       "Permissive file permissions",
		Severity:    SeverityMedium,
		Why:         "World-writable or broadly readable files can leak or allow modification of sensitive data.",
		Remediation: "Use 0600 for secrets and 0644 or less for public read-only files.",
		Match:       RuleMatch{Type: MatchCallPermissiveChmod},
		Fixture: `package main

import "os"

func f() { os.Chmod("f", 0777) }
`,
	},
	{
		ID:          "GO-TLS-SKIP-VERIFY",
		Title:       "TLS certificate verification disabled",
		Severity:    SeverityHigh,
		Why:         "Disabling certificate verification allows man-in-the-middle attacks on TLS connections.",
		Remediation: "Keep certificate verification enabled and configure trusted roots or server names explicitly.",
		Match: RuleMatch{
			Type:         MatchCompositeFieldBool,
			TypeSelector: "tls.Config",
			Field:        "InsecureSkipVerify",
			BoolValue:    true,
		},
		Fixture: `package main

import "crypto/tls"

func f() { _ = &tls.Config{InsecureSkipVerify: true} }
`,
	},
	{
		ID:          "GO-XSS-UNSAFE-CAST",
		Title:       "Unsafe HTML/JS/CSS template type cast",
		Severity:    SeverityHigh,
		Why:         "Casting to template.HTML, template.JS, or template.URL bypasses Go's contextual HTML escaping and enables XSS.",
		Remediation: "Never cast untrusted input to template type aliases; rely on the template engine's automatic escaping.",
		Match: RuleMatch{
			Type: MatchCall,
			Functions: []string{
				"html/template.HTML", "html/template.JS",
				"html/template.URL", "html/template.Attr", "html/template.CSS",
			},
		},
		Fixture: `package main

import "html/template"

func f() { _ = template.HTML("x") }
`,
	},
	{
		ID:          "GO-EXEC-SYSCALL",
		Title:       "Low-level process execution via syscall",
		Severity:    SeverityHigh,
		Why:         "Direct syscall-level process execution bypasses standard argument handling and is difficult to audit for injection.",
		Remediation: "Use os/exec with explicit argument lists; avoid the syscall package for process management.",
		Match: RuleMatch{
			Type:      MatchCall,
			Functions: []string{"syscall.Exec", "syscall.ForkExec", "syscall.StartProcess"},
		},
		Fixture: `package main

import "syscall"

func f() { syscall.Exec("/bin/sh", nil, nil) }
`,
	},
	{
		ID:          "GO-OS-START-PROCESS",
		Title:       "Raw process launch via os.StartProcess",
		Severity:    SeverityHigh,
		Why:         "os.StartProcess provides minimal safety guarantees compared to os/exec.Command.",
		Remediation: "Use os/exec.Command with structured arguments and a controlled environment.",
		Match: RuleMatch{
			Type:      MatchCall,
			Functions: []string{"os.StartProcess"},
		},
		Fixture: `package main

import "os"

func f() { os.StartProcess("", nil, nil) }
`,
	},
	{
		ID:          "GO-XML-EXTERNAL-ENTITY",
		Title:       "XML parsing without explicit external entity control",
		Severity:    SeverityMedium,
		Why:         "Consuming untrusted XML without reviewing XXE protections can expose internal resources.",
		Remediation: "Validate XML schema before parsing; do not process untrusted XML from external sources without review.",
		Match: RuleMatch{
			Type:      MatchCall,
			Functions: []string{"encoding/xml.NewDecoder", "encoding/xml.Unmarshal"},
		},
		Fixture: `package main

import "encoding/xml"

func f() { xml.NewDecoder(nil) }
`,
	},
	{
		ID:          "GO-GOB-DECODE",
		Title:       "Unsafe deserialization via encoding/gob",
		Severity:    SeverityMedium,
		Why:         "Decoding untrusted gob payloads into complex or interface-typed objects can create unexpected state.",
		Remediation: "Treat decoded data as untrusted; validate schema and types explicitly.",
		Match: RuleMatch{
			Type:      MatchCall,
			Functions: []string{"encoding/gob.NewDecoder"},
		},
		Fixture: `package main

import "encoding/gob"

func f() { gob.NewDecoder(nil) }
`,
	},
	{
		ID:          "GO-TEMPFILE-INSECURE",
		Title:       "Insecure temporary file creation",
		Severity:    SeverityLow,
		Why:         "Temporary files in shared directories can be accessed or manipulated by other processes.",
		Remediation: "Use os.CreateTemp with a controlled directory and restrict permissions to 0600.",
		Match: RuleMatch{
			Type:      MatchCall,
			Functions: []string{"os.CreateTemp", "io/ioutil.TempFile"},
		},
		Fixture: `package main

import "os"

func f() { os.CreateTemp("", "") }
`,
	},
	{
		ID:          "GO-UNSAFE-POINTER",
		Title:       "Use of unsafe.Pointer",
		Severity:    SeverityMedium,
		Why:         "Unsafe pointer operations bypass Go's type system and memory safety guarantees.",
		Remediation: "Avoid the unsafe package outside well-reviewed, performance-critical low-level code; never use with untrusted data.",
		Match: RuleMatch{
			Type:      MatchCall,
			Functions: []string{"unsafe.Pointer", "unsafe.Add", "unsafe.Slice"},
		},
		Fixture: `package main

import "unsafe"

func f(x int) unsafe.Pointer { return unsafe.Pointer(&x) }
`,
	},
	{
		ID:          "GO-CRYPTO-BLOWFISH",
		Title:       "Weak cipher (Blowfish)",
		Severity:    SeverityHigh,
		Why:         "Blowfish has a 64-bit block size making it vulnerable to Sweet32 birthday attacks in long sessions.",
		Remediation: "Replace with AES-GCM or ChaCha20-Poly1305.",
		Match: RuleMatch{
			Type:    MatchImport,
			Package: "golang.org/x/crypto/blowfish",
		},
		Fixture: `package main

import _ "golang.org/x/crypto/blowfish"
`,
	},
	{
		ID:          "GO-CRYPTO-CAST5",
		Title:       "Weak cipher (CAST5)",
		Severity:    SeverityHigh,
		Why:         "CAST5 uses a 64-bit block and is considered cryptographically weak for modern use.",
		Remediation: "Replace with AES-GCM or ChaCha20-Poly1305.",
		Match: RuleMatch{
			Type:    MatchImport,
			Package: "golang.org/x/crypto/cast5",
		},
		Fixture: `package main

import _ "golang.org/x/crypto/cast5"
`,
	},
	{
		ID:          "GO-CRYPTO-MD4",
		Title:       "Weak hash (MD4)",
		Severity:    SeverityHigh,
		Why:         "MD4 is cryptographically broken with known collision attacks.",
		Remediation: "Use SHA-256 or SHA-3 for cryptographic hashing.",
		Match: RuleMatch{
			Type:    MatchImport,
			Package: "golang.org/x/crypto/md4",
		},
		Fixture: `package main

import _ "golang.org/x/crypto/md4"
`,
	},
	{
		ID:          "GO-CRYPTO-TEA",
		Title:       "Weak cipher (TEA/XTEA)",
		Severity:    SeverityHigh,
		Why:         "TEA and XTEA have known related-key weaknesses and use a 64-bit block size.",
		Remediation: "Replace with AES-GCM or ChaCha20-Poly1305.",
		Match: RuleMatch{
			Type:    MatchImport,
			Package: "golang.org/x/crypto/tea",
		},
		Fixture: `package main

import _ "golang.org/x/crypto/tea"
`,
	},
	{
		ID:          "GO-DEBUG-PPROF",
		Title:       "Profiling endpoint registered (net/http/pprof)",
		Severity:    SeverityMedium,
		Why:         "Importing net/http/pprof registers /debug/pprof/* HTTP handlers that expose heap dumps, goroutine stacks, and CPU profiles.",
		Remediation: "Remove the pprof import in production builds or restrict /debug/ paths behind authentication middleware.",
		Match: RuleMatch{
			Type:    MatchImport,
			Package: "net/http/pprof",
		},
		Fixture: `package main

import _ "net/http/pprof"
`,
	},
	{
		ID:          "GO-YAML-UNSAFE",
		Title:       "YAML library imported — review for unsafe deserialization",
		Severity:    SeverityMedium,
		Why:         "Unmarshaling untrusted YAML into interface{} or complex types can trigger unexpected code paths.",
		Remediation: "Unmarshal into strictly typed structs; reject unexpected fields; do not process untrusted YAML.",
		Match: RuleMatch{
			Type:     MatchImport,
			Packages: []string{"gopkg.in/yaml.v2", "gopkg.in/yaml.v3", "sigs.k8s.io/yaml"},
		},
		Fixture: `package main

import _ "gopkg.in/yaml.v3"
`,
	},
}
