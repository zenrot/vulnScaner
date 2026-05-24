package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	goparser "go/parser"
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
		codeqlLimit = 2000
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
	importFindings := applyImportRules(selected)
	findings = append(findings, importFindings...)
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
			"GOWORK=off",
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

	ruleIdx := buildRuleIndex(BuiltinRules)

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
				applyCallRules(n, importMaps[idx], ruleIdx, add)
			case *ast.CompositeLit:
				applyCompositeBoolRules(n, ruleIdx, add)
			case *ast.ValueSpec:
				applyValueSpecSecretRules(n, ruleIdx.secretValue, add)
			case *ast.AssignStmt:
				applyAssignSecretRules(n, ruleIdx.secretValue, add)
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

type adderFn = func(token.Pos, string, string, Severity, string, string, string)

func adderFor(fset *token.FileSet, absPath string, out *[]Finding) adderFn {
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

type rulesByType struct {
	call          []Rule
	callPkg       []Rule
	callShell     []Rule
	callChmod     []Rule
	compositeBool []Rule
	secretValue   []Rule
}

func buildRuleIndex(rules []Rule) rulesByType {
	var idx rulesByType
	for _, r := range rules {
		switch r.Match.Type {
		case MatchCall:
			idx.call = append(idx.call, r)
		case MatchCallPkg:
			idx.callPkg = append(idx.callPkg, r)
		case MatchCallShell:
			idx.callShell = append(idx.callShell, r)
		case MatchCallPermissiveChmod:
			idx.callChmod = append(idx.callChmod, r)
		case MatchCompositeFieldBool:
			idx.compositeBool = append(idx.compositeBool, r)
		case MatchSecretValue:
			idx.secretValue = append(idx.secretValue, r)
		}
	}
	return idx
}

func applyCallRules(call *ast.CallExpr, imports map[string]string, idx rulesByType, add adderFn) {
	pkg, fn := selector(call.Fun)
	importPath := imports[pkg]
	fullName := importPath + "." + fn

	for _, rule := range idx.call {
		for _, f := range rule.Match.Functions {
			if fullName == f {
				add(call.Pos(), rule.ID, rule.Title, rule.Severity, fullName, rule.Why, rule.Remediation)
				break
			}
		}
	}

	if importPath != "" {
		for _, rule := range idx.callPkg {
			if importPath == rule.Match.Package {
				add(call.Pos(), rule.ID, rule.Title, rule.Severity, pkg+"."+fn, rule.Why, rule.Remediation)
			}
		}
	}

	for _, rule := range idx.callShell {
		if importPath == "os/exec" && fn == "Command" && invokesShell(call.Args) {
			add(call.Pos(), rule.ID, rule.Title, rule.Severity, "exec.Command invoking a shell", rule.Why, rule.Remediation)
		}
	}

	for _, rule := range idx.callChmod {
		if importPath == "os" && fn == "Chmod" && len(call.Args) >= 2 && isPermissiveMode(call.Args[1]) {
			add(call.Pos(), rule.ID, rule.Title, rule.Severity, "os.Chmod with broad permissions", rule.Why, rule.Remediation)
		}
	}
}

func applyCompositeBoolRules(lit *ast.CompositeLit, idx rulesByType, add adderFn) {
	typeName := selectorString(lit.Type)
	for _, rule := range idx.compositeBool {
		if typeName != rule.Match.TypeSelector {
			continue
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != rule.Match.Field {
				continue
			}
			value, ok := kv.Value.(*ast.Ident)
			if !ok {
				continue
			}
			expected := "false"
			if rule.Match.BoolValue {
				expected = "true"
			}
			if value.Name == expected {
				add(kv.Pos(), rule.ID, rule.Title, rule.Severity,
					rule.Match.Field+": "+expected, rule.Why, rule.Remediation)
			}
		}
	}
}

func applyValueSpecSecretRules(spec *ast.ValueSpec, rules []Rule, add adderFn) {
	for i, name := range spec.Names {
		if i >= len(spec.Values) {
			continue
		}
		applySecretCheck(name, spec.Values[i], spec.Pos(), rules, add)
	}
}

func applyAssignSecretRules(stmt *ast.AssignStmt, rules []Rule, add adderFn) {
	for i, lhs := range stmt.Lhs {
		name, ok := lhs.(*ast.Ident)
		if !ok || i >= len(stmt.Rhs) {
			continue
		}
		applySecretCheck(name, stmt.Rhs[i], stmt.Pos(), rules, add)
	}
}

func applySecretCheck(name *ast.Ident, val ast.Expr, pos token.Pos, rules []Rule, add adderFn) {
	lit, ok := val.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return
	}
	str, err := strconv.Unquote(lit.Value)
	if err != nil {
		return
	}
	for _, rule := range rules {
		if isSecretName(name.Name, rule.Match.NamePatterns) && isSecretStringValue(str, rule.Match.MinLength) {
			add(pos, rule.ID, rule.Title, rule.Severity, name.Name, rule.Why, rule.Remediation)
		}
	}
}

func isSecretName(name string, patterns []string) bool {
	lower := strings.ToLower(name)
	matched := false
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, suffix := range []string{
		"controller", "handler", "manager", "cleaner", "signer",
		"publisher", "collector", "reconciler", "watcher", "listener",
		"provider", "builder", "factory", "registry",
	} {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	return true
}

func isSecretStringValue(s string, minLen int) bool {
	if strings.Contains(s, "-----BEGIN") {
		return true
	}
	return len(s) >= minLen
}

func applyImportRules(files []string) []Finding {
	var importRules []Rule
	for _, r := range BuiltinRules {
		if r.Match.Type == MatchImport {
			importRules = append(importRules, r)
		}
	}
	if len(importRules) == 0 {
		return nil
	}
	fset := token.NewFileSet()
	var findings []Finding
	for _, path := range files {
		f, err := goparser.ParseFile(fset, path, nil, goparser.ImportsOnly)
		if err != nil {
			continue
		}
		for _, imp := range f.Imports {
			impPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			for _, rule := range importRules {
				if importMatchesRule(impPath, rule) {
					pos := fset.Position(imp.Pos())
					findings = append(findings, Finding{
						RuleID:       rule.ID,
						Title:        rule.Title,
						Severity:     rule.Severity,
						File:         path,
						Line:         pos.Line,
						Column:       pos.Column,
						Evidence:     impPath,
						WhyItMatters: rule.Why,
						Remediation:  rule.Remediation,
					})
				}
			}
		}
	}
	return findings
}

func importMatchesRule(importPath string, rule Rule) bool {
	if len(rule.Match.Packages) > 0 {
		for _, p := range rule.Match.Packages {
			if importPath == p {
				return true
			}
		}
		return false
	}
	return importPath == rule.Match.Package
}

func checkTaintLite(file *ast.File, imports map[string]string, add adderFn) {
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
			}
			return true
		})
	}
}

func checkTaintSink(call *ast.CallExpr, imports map[string]string, tainted map[string]bool, add adderFn) {
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
