package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"vulnscanner/internal/logging"

	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/packages"
)

type Options struct {
	Workers        int
	Incremental    bool
	ChangedOnly    bool
	CacheFile      string
	IncludeTests   bool
	SkipGitIgnore  bool
	CodeQLMaxFiles int
	OnScanStatus   func(msg string)
}

type Metrics struct {
	FilesDiscovered int           `json:"files_discovered"`
	FilesScanned    int           `json:"files_scanned"`
	FilesSkipped    int           `json:"files_skipped"`
	ScanDuration    time.Duration `json:"scan_duration"`
}

type Result struct {
	Findings []Finding `json:"findings"`
	Metrics  Metrics   `json:"metrics"`
}

type fileCache struct {
	Hashes map[string]string `json:"hashes"`
}

const defaultPackagesLoadTimeout = 45 * time.Second

func Scan(root string) ([]Finding, error) {
	res, err := ScanWithOptions(root, Options{})
	if err != nil {
		return nil, err
	}
	return res.Findings, nil
}

func ScanWithOptions(root string, opts Options) (Result, error) {
	start := time.Now()
	if opts.Workers <= 0 {
		opts.Workers = runtime.NumCPU()
	}
	if opts.CacheFile == "" {
		opts.CacheFile = filepath.Join(root, ".sastcache.json")
	}

	files, err := collectFiles(root, opts)
	if err != nil {
		return Result{}, err
	}
	metrics := Metrics{FilesDiscovered: len(files)}

	var oldCache fileCache
	if opts.Incremental {
		oldCache = readCache(opts.CacheFile)
		if oldCache.Hashes == nil {
			oldCache.Hashes = map[string]string{}
		}
	}

	selected := make([]string, 0, len(files))
	newCache := fileCache{Hashes: map[string]string{}}
	for _, path := range files {
		hash, hashErr := fileHash(path)
		if hashErr != nil {
			return Result{}, hashErr
		}
		newCache.Hashes[path] = hash
		if opts.Incremental && oldCache.Hashes[path] == hash {
			metrics.FilesSkipped++
			continue
		}
		selected = append(selected, path)
	}

	codeqlLimit := opts.CodeQLMaxFiles
	if codeqlLimit <= 0 {
		codeqlLimit = 2000 // default: CodeQL for projects up to 2 000 files
	}

	var findings []Finding

	useCodeQL := IsCodeQLAvailable() && len(selected) <= codeqlLimit
	if !useCodeQL && IsCodeQLAvailable() {
		logging.L().Info("codeql skipped",
			"reason", "file_limit",
			"files", len(selected),
			"limit", codeqlLimit,
		)
	}

	if useCodeQL {
		cqFindings, err := ScanWithCodeQL(root, selected, opts.OnScanStatus)
		if err != nil {
			logging.L().Warn("codeql failed, falling back to built-in scanners", "err", err)
			findings, err = scanAllFiles(root, selected, opts.Workers)
			if err != nil {
				return Result{}, err
			}
		} else {
			builtinFindings, mergeErr := scanAllFiles(root, selected, opts.Workers)
			if mergeErr != nil {
				logging.L().Warn("builtin scan for merge failed, continuing with codeql findings only",
					"codeql_findings", len(cqFindings),
					"err", mergeErr,
				)
				findings = cqFindings
			} else {
				findings = mergeFindings(cqFindings, builtinFindings)
			}
		}
	} else {
		var err error
		findings, err = scanAllFiles(root, selected, opts.Workers)
		if err != nil {
			return Result{}, err
		}
	}

	if IsGosecAvailable() {
		gosecFindings, err := ScanWithGosec(root, opts.OnScanStatus)
		if err != nil {
			logging.L().Warn("gosec scan failed, continuing with existing findings", "err", err)
		} else {
			findings = mergeFindings(findings, gosecFindings)
			logging.L().Info("gosec findings merged",
				"gosec_findings", len(gosecFindings),
				"total_findings", len(findings),
			)
		}
	} else {
		logging.L().Info("gosec skipped", "reason", "binary_not_found")
	}

	if IsGovulncheckAvailable() {
		govulnFindings, err := ScanWithGovulncheck(root, opts.OnScanStatus)
		if err != nil {
			logging.L().Warn("govulncheck scan failed, continuing with existing findings", "err", err)
		} else {
			findings = mergeFindings(findings, govulnFindings)
			logging.L().Info("govulncheck findings merged",
				"govulncheck_findings", len(govulnFindings),
				"total_findings", len(findings),
			)
		}
	} else {
		logging.L().Info("govulncheck skipped", "reason", "binary_not_found")
	}

	if opts.Incremental {
		if err := writeCache(opts.CacheFile, newCache); err != nil {
			return Result{}, err
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File == findings[j].File {
			if findings[i].Line == findings[j].Line {
				return findings[i].RuleID < findings[j].RuleID
			}
			return findings[i].Line < findings[j].Line
		}
		return findings[i].File < findings[j].File
	})

	metrics.FilesScanned = len(selected)
	metrics.ScanDuration = time.Since(start)
	return Result{Findings: findings, Metrics: metrics}, nil
}

func mergeFindings(codeql, builtin []Finding) []Finding {
	seen := make(map[string]struct{}, len(codeql)+len(builtin))
	result := make([]Finding, 0, len(codeql)+len(builtin))
	appendUnique := func(items []Finding) {
		for _, f := range items {
			key := findingIdentity(f)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, f)
		}
	}
	appendUnique(codeql)
	appendUnique(builtin)
	return result
}

func findingIdentity(f Finding) string {
	return fmt.Sprintf("%s|%s|%d|%d", strings.ToUpper(strings.TrimSpace(f.RuleID)), f.File, f.Line, f.Column)
}

func scanAllFiles(root string, selected []string, workers int) ([]Finding, error) {
	started := time.Now()
	timeout := packagesLoadTimeout()
	logging.L().Info("builtin scan started",
		"selected_files", len(selected),
		"workers", workers,
		"packages_timeout", timeout.String(),
	)
	findings, err := scanPackages(root, selected, timeout)
	if err != nil {
		return nil, err
	}
	logging.L().Info("builtin scan completed",
		"selected_files", len(selected),
		"findings", len(findings),
		"duration", time.Since(started).String(),
	)
	return findings, nil
}

func packagesLoadTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("SAST_PACKAGES_TIMEOUT_SEC")); raw != "" {
		if sec, err := strconv.Atoi(raw); err == nil && sec > 0 {
			return time.Duration(sec) * time.Second
		}
	}
	return defaultPackagesLoadTimeout
}

func ensureGoMod(root string) (cleanup func(), err error) {
	modPath := filepath.Join(root, "go.mod")
	if _, statErr := os.Stat(modPath); statErr == nil {
		return func() {}, nil
	}
	content := "module scan-target\n\ngo 1.21\n"
	if writeErr := os.WriteFile(modPath, []byte(content), 0644); writeErr != nil {
		return func() {}, fmt.Errorf("cannot create go.mod: %w", writeErr)
	}
	return func() { os.Remove(modPath) }, nil
}

func scanPackages(root string, selected []string, timeout time.Duration) ([]Finding, error) {
	cleanup, err := ensureGoMod(root)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cfg := &packages.Config{
		Mode:    packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedSyntax,
		Dir:     root,
		Context: ctx,
		Env: append(os.Environ(),
			"GONOSUMCHECK=*",
			"GONOSUMDB=*",
			"GOPROXY=off",
			"GOFLAGS=-mod=mod",
		),
	}
	pkgs, err := packages.Load(cfg, "./...")
	if ctx.Err() != nil {
		return nil, fmt.Errorf("go/packages timeout after %s: %w", timeout, ctx.Err())
	}
	if err != nil {
		return nil, err
	}

	pkgErrs := 0
	for _, p := range pkgs {
		pkgErrs += len(p.Errors)
	}
	if pkgErrs > 0 {
		logging.L().Info("go/packages: packages with errors (missing deps expected for uploaded archives)",
			"count", pkgErrs)
	}

	selectedSet := make(map[string]struct{}, len(selected))
	for _, p := range selected {
		abs, _ := filepath.Abs(p)
		selectedSet[abs] = struct{}{}
	}

	var findings []Finding
	for _, pkg := range pkgs {
		filePaths := pkg.CompiledGoFiles
		if len(filePaths) == 0 {
			filePaths = pkg.GoFiles
		}
		if len(pkg.Syntax) == 0 || len(filePaths) == 0 {
			continue
		}

		importMaps := make([]map[string]string, len(pkg.Syntax))
		fileIndex := make(map[*ast.File]int, len(pkg.Syntax))
		for i, f := range pkg.Syntax {
			importMaps[i] = importAliases(f)
			fileIndex[f] = i
		}

		insp := inspector.New(pkg.Syntax)
		nodes := []ast.Node{
			(*ast.CallExpr)(nil),
			(*ast.CompositeLit)(nil),
			(*ast.ValueSpec)(nil),
			(*ast.AssignStmt)(nil),
		}
		insp.Preorder(nodes, func(node ast.Node) {
			file := owningFile(pkg.Syntax, node.Pos(), node.End())
			if file == nil {
				return
			}
			idx := fileIndex[file]
			if idx >= len(filePaths) {
				return
			}
			abs, _ := filepath.Abs(filePaths[idx])
			if _, ok := selectedSet[abs]; !ok {
				return
			}
			add := adderFor(pkg.Fset, abs, &findings)
			switch n := node.(type) {
			case *ast.CallExpr:
				checkCall(n, importMaps[idx], add)
			case *ast.CompositeLit:
				checkComposite(n, add)
			case *ast.ValueSpec:
				checkValueSpec(n, add)
			case *ast.AssignStmt:
				checkAssignStmt(n, add)
			}
		})

		for i, file := range pkg.Syntax {
			if i >= len(filePaths) {
				continue
			}
			abs, _ := filepath.Abs(filePaths[i])
			if _, ok := selectedSet[abs]; !ok {
				continue
			}
			checkTaintLite(file, importMaps[i], adderFor(pkg.Fset, abs, &findings))
		}
	}
	return findings, nil
}

func owningFile(files []*ast.File, start, end token.Pos) *ast.File {
	for _, f := range files {
		if f.Pos() <= start && end <= f.End() {
			return f
		}
	}
	return nil
}

func adderFor(fset *token.FileSet, absPath string, out *[]Finding) func(token.Pos, string, string, Severity, string, string, string) {
	return func(pos token.Pos, ruleID, title string, severity Severity, evidence, why, remediation string) {
		position := fset.Position(pos)
		*out = append(*out, Finding{
			RuleID:       ruleID,
			Title:        title,
			Severity:     severity,
			File:         absPath,
			Line:         position.Line,
			Column:       position.Column,
			Evidence:     evidence,
			WhyItMatters: why,
			Remediation:  remediation,
		})
	}
}

func collectFiles(root string, opts Options) ([]string, error) {
	if opts.ChangedOnly {
		return changedSourceFiles(root, opts.IncludeTests)
	}
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "bin", "dist", "build":
				return filepath.SkipDir
			}
			return nil
		}
		if isSupportedSourceFile(path, opts.IncludeTests) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func isSupportedSourceFile(path string, includeTests bool) bool {
	base := filepath.Base(path)
	if !strings.HasSuffix(base, ".go") {
		return false
	}
	return includeTests || !strings.HasSuffix(base, "_test.go")
}

func changedSourceFiles(root string, includeTests bool) ([]string, error) {
	cmd := exec.Command("git", "-C", root, "diff", "--name-only", "--diff-filter=ACMR", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		cmd = exec.Command("git", "-C", root, "ls-files", "-m", "-o", "--exclude-standard")
		out, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to collect changed files from git: %w", err)
		}
	}
	lines := strings.Split(string(out), "\n")
	files := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		abs := filepath.Join(root, trimmed)
		if !isSupportedSourceFile(abs, includeTests) {
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			files = append(files, abs)
		}
	}
	return files, nil
}


func checkTaintLite(file *ast.File, imports map[string]string, add func(token.Pos, string, string, Severity, string, string, string)) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		tainted := map[string]bool{}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.AssignStmt:
				for i, lhs := range n.Lhs {
					ident, ok := lhs.(*ast.Ident)
					if !ok || i >= len(n.Rhs) {
						continue
					}
					if isSourceCall(n.Rhs[i], imports) {
						tainted[ident.Name] = true
					}
					if isSanitizedCall(n.Rhs[i], imports) {
						tainted[ident.Name] = false
					}
				}
			case *ast.ValueSpec:
				for i, name := range n.Names {
					if i < len(n.Values) && isSourceCall(n.Values[i], imports) {
						tainted[name.Name] = true
					}
				}
			case *ast.CallExpr:
				checkTaintSink(n, imports, tainted, add)
				checkUnsafeDeserialize(n, imports, add)
				checkInsecureTempFile(n, imports, add)
			}
			return true
		})
	}
}

func checkTaintSink(call *ast.CallExpr, imports map[string]string, tainted map[string]bool, add func(token.Pos, string, string, Severity, string, string, string)) {
	pkg, fn := selector(call.Fun)
	importPath := imports[pkg]
	fullName := importPath + "." + fn

	if fullName == "os/exec.Command" && hasTaintedArg(call.Args, tainted) {
		add(call.Pos(), "GO-CMD-INJECTION-TAINT", "Potential command injection via tainted input", SeverityHigh, "tainted data reaches exec.Command",
			"User-controlled input that reaches command execution can allow arbitrary command injection.",
			"Avoid shell execution paths and strictly validate/allowlist external inputs before invoking commands.")
	}

	if (fullName == "net/http.Get" || fullName == "net/http.Post") && len(call.Args) > 0 && isTaintedExpr(call.Args[0], tainted) {
		add(call.Pos(), "GO-SSRF-TAINT", "Potential SSRF via tainted URL", SeverityHigh, "tainted data used as outbound URL",
			"User-controlled URLs can force server-side requests to internal resources and cloud metadata endpoints.",
			"Validate destination URLs against strict allowlists and block private/internal address ranges.")
	}

	if (fullName == "os.Open" || fullName == "os.ReadFile") && len(call.Args) > 0 && isTaintedExpr(call.Args[0], tainted) {
		add(call.Pos(), "GO-PATH-TRAVERSAL-TAINT", "Potential path traversal via tainted path", SeverityHigh, "tainted data reaches file path sink",
			"Untrusted path segments can escape intended directories and expose sensitive files.",
			"Use filepath.Clean plus prefix checks against a fixed base directory, and reject traversal patterns.")
	}
}

func checkUnsafeDeserialize(call *ast.CallExpr, imports map[string]string, add func(token.Pos, string, string, Severity, string, string, string)) {
	pkg, fn := selector(call.Fun)
	importPath := imports[pkg]
	fullName := importPath + "." + fn
	if fullName == "encoding/gob.Decode" || fullName == "gopkg.in/yaml.v2.Unmarshal" || fullName == "gopkg.in/yaml.v3.Unmarshal" {
		add(call.Pos(), "GO-DESERIALIZE-UNTRUSTED", "Potential unsafe deserialization", SeverityMedium, fullName,
			"Decoding untrusted payloads into complex objects can trigger unsafe states or abuse business logic paths.",
			"Treat decoded data as untrusted, validate schema/fields explicitly, and minimize accepted types.")
	}
}

func checkInsecureTempFile(call *ast.CallExpr, imports map[string]string, add func(token.Pos, string, string, Severity, string, string, string)) {
	pkg, fn := selector(call.Fun)
	importPath := imports[pkg]
	if (importPath == "io/ioutil" && fn == "TempFile") || (importPath == "os" && fn == "CreateTemp") {
		add(call.Pos(), "GO-TEMPFILE-REVIEW", "Temp file usage requires security review", SeverityLow, importPath+"."+fn,
			"Temporary files can leak data when created in shared locations or with overly broad access controls.",
			"Prefer restrictive permissions, avoid sensitive content in temp files, and ensure cleanup is guaranteed.")
	}
}

func isSourceCall(expr ast.Expr, imports map[string]string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	pkg, fn := selector(call.Fun)
	importPath := imports[pkg]
	if importPath == "os" && fn == "Getenv" {
		return true
	}
	if fn == "FormValue" || fn == "Param" {
		return true
	}
	if fn == "Query" || fn == "PostFormValue" {
		return true
	}
	return false
}

func isSanitizedCall(expr ast.Expr, imports map[string]string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	pkg, fn := selector(call.Fun)
	return imports[pkg] == "path/filepath" && fn == "Clean"
}

func hasTaintedArg(args []ast.Expr, tainted map[string]bool) bool {
	for _, arg := range args {
		if isTaintedExpr(arg, tainted) {
			return true
		}
	}
	return false
}

func isTaintedExpr(expr ast.Expr, tainted map[string]bool) bool {
	switch n := expr.(type) {
	case *ast.Ident:
		return tainted[n.Name]
	case *ast.BinaryExpr:
		return isTaintedExpr(n.X, tainted) || isTaintedExpr(n.Y, tainted)
	case *ast.CallExpr:
		for _, arg := range n.Args {
			if isTaintedExpr(arg, tainted) {
				return true
			}
		}
	}
	return false
}

func importAliases(file *ast.File) map[string]string {
	imports := make(map[string]string)
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := filepath.Base(path)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports[name] = path
	}
	return imports
}

func checkCall(call *ast.CallExpr, imports map[string]string, add func(token.Pos, string, string, Severity, string, string, string)) {
	pkg, fn := selector(call.Fun)
	importPath := imports[pkg]
	fullName := importPath + "." + fn

	switch fullName {
	case "crypto/md5.New", "crypto/sha1.New", "crypto/des.NewCipher", "crypto/rc4.NewCipher":
		add(call.Pos(), "GO-CRYPTO-WEAK", "Weak cryptographic primitive", SeverityHigh, fullName,
			"Weak or broken cryptographic primitives can enable collision, downgrade, or confidentiality attacks.",
			"Use modern primitives such as SHA-256/SHA-512 for hashing needs or AES-GCM/ChaCha20-Poly1305 for encryption.")
	case "net/http.ListenAndServe":
		add(call.Pos(), "GO-HTTP-NO-TLS", "HTTP server without TLS", SeverityMedium, fullName,
			"Plain HTTP can expose credentials, session tokens, and sensitive application data in transit.",
			"Terminate TLS at a trusted proxy or use ListenAndServeTLS when the service is directly exposed.")
	}

	if importPath == "math/rand" && strings.HasPrefix(fn, "Int") {
		add(call.Pos(), "GO-RAND-INSECURE", "Potentially insecure random source", SeverityMedium, pkg+"."+fn,
			"math/rand is deterministic and is not suitable for tokens, secrets, nonces, or security decisions.",
			"Use crypto/rand for security-sensitive randomness.")
	}

	if importPath == "os" && fn == "Chmod" && len(call.Args) >= 2 && isPermissiveMode(call.Args[1]) {
		add(call.Pos(), "GO-FILE-PERMISSIVE", "Permissive file permissions", SeverityMedium, "os.Chmod with broad permissions",
			"World-writable or broadly readable files can leak or allow modification of sensitive data.",
			"Use the narrowest permissions possible, commonly 0600 for secrets and 0644 or less for public read-only files.")
	}

	if importPath == "os/exec" && fn == "Command" && invokesShell(call.Args) {
		add(call.Pos(), "GO-CMD-SHELL", "Shell command execution", SeverityHigh, "exec.Command invoking a shell",
			"Passing dynamic data through a shell creates command injection risk.",
			"Call the target executable directly with structured arguments and validate any user-controlled values.")
	}
}

func checkComposite(lit *ast.CompositeLit, add func(token.Pos, string, string, Severity, string, string, string)) {
	if selectorString(lit.Type) != "tls.Config" {
		return
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "InsecureSkipVerify" {
			continue
		}
		if value, ok := kv.Value.(*ast.Ident); ok && value.Name == "true" {
			add(kv.Pos(), "GO-TLS-SKIP-VERIFY", "TLS certificate verification disabled", SeverityHigh, "InsecureSkipVerify: true",
				"Disabling certificate verification allows man-in-the-middle attacks.",
				"Keep certificate verification enabled and configure trusted roots or server names explicitly.")
		}
	}
}

func checkValueSpec(spec *ast.ValueSpec, add func(token.Pos, string, string, Severity, string, string, string)) {
	for i, name := range spec.Names {
		if !secretLike(name.Name) || i >= len(spec.Values) {
			continue
		}
		if lit, ok := spec.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING && secretValueLike(lit.Value) {
			add(spec.Pos(), "GO-HARDCODED-SECRET", "Hardcoded secret-like value", SeverityHigh, name.Name,
				"Secrets committed to source control are difficult to rotate and can be recovered from history.",
				"Load secrets from a secret manager, environment, or runtime configuration outside version control.")
		}
	}
}

func checkAssignStmt(stmt *ast.AssignStmt, add func(token.Pos, string, string, Severity, string, string, string)) {
	for i, lhs := range stmt.Lhs {
		name, ok := lhs.(*ast.Ident)
		if !ok || !secretLike(name.Name) || i >= len(stmt.Rhs) {
			continue
		}
		if lit, ok := stmt.Rhs[i].(*ast.BasicLit); ok && lit.Kind == token.STRING && secretValueLike(lit.Value) {
			add(stmt.Pos(), "GO-HARDCODED-SECRET", "Hardcoded secret-like value", SeverityHigh, name.Name,
				"Secrets committed to source control are difficult to rotate and can be recovered from history.",
				"Load secrets from a secret manager, environment, or runtime configuration outside version control.")
		}
	}
}

func selector(expr ast.Expr) (string, string) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", sel.Sel.Name
	}
	return pkg.Name, sel.Sel.Name
}

func selectorString(expr ast.Expr) string {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return sel.Sel.Name
	}
	return pkg.Name + "." + sel.Sel.Name
}

func invokesShell(args []ast.Expr) bool {
	if len(args) < 2 {
		return false
	}
	cmd, ok := stringLiteral(args[0])
	if !ok {
		return false
	}
	flag, ok := stringLiteral(args[1])
	if !ok {
		return false
	}
	cmd = strings.ToLower(filepath.Base(cmd))
	return (cmd == "sh" || cmd == "bash" || cmd == "cmd" || cmd == "powershell" || cmd == "pwsh") &&
		(flag == "-c" || strings.EqualFold(flag, "/c"))
}

func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

func isPermissiveMode(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return false
	}
	value, err := strconv.ParseInt(lit.Value, 0, 64)
	if err != nil {
		return false
	}
	return value&0002 != 0 || value == 0777 || value == 0666
}

func secretLike(name string) bool {
	lower := strings.ToLower(name)
	keywords := []string{"password", "passwd", "secret", "token", "apikey", "api_key", "privatekey", "private_key"}
	matched := false
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	nonsecret := []string{
		"controller", "handler", "manager", "cleaner", "signer",
		"publisher", "collector", "reconciler", "watcher", "listener",
		"provider", "builder", "factory", "registry",
	}
	for _, suffix := range nonsecret {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	return true
}

func secretValueLike(raw string) bool {
	value, err := strconv.Unquote(raw)
	if err != nil {
		return false
	}
	if strings.Contains(value, "-----BEGIN") {
		return true
	}
	return len(value) >= 16
}

func fileHash(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), nil
}

func readCache(path string) fileCache {
	var c fileCache
	data, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	_ = json.Unmarshal(data, &c)
	return c
}

func writeCache(path string, c fileCache) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
