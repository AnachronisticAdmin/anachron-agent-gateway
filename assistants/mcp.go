// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0
// Derived from the owner-approved snapshot; modified for the standalone candidate.
// See PROVENANCE.md for source and intentional behavior changes.

package assistants

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/acp"
)

// MetaMCPServers carries the MCP servers (ACP McpServer objects) to attach to
// a new task's agent session. Only SendMessageRequest.metadata is read:
// message metadata is kept in task history, and these objects may carry
// credentials, so ValidateMessage refuses the key there before anything is
// stored.
const MetaMCPServers = "anachron.mcpServers"

// MCP server transports accepted in MetaMCPServers.
const (
	MCPStdio = "stdio"
	MCPHTTP  = "http"
)

const (
	maxMCPPayload = 64 << 10
	maxMCPServers = 16
	maxMCPList    = 64
	maxMCPValue   = 8 << 10
	maxMCPPath    = 4 << 10
)

var (
	mcpNameRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	envNameRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	headerNameRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
	// secretNameRE selects the env, header and query names whose values are
	// masked in task output (the gateway applies the same idea to its own
	// environment).
	secretNameRE = regexp.MustCompile(`(?i)(KEY|TOKEN|SECRET|PASS|CREDENTIAL|AUTH|COOKIE|SESSION|SIG)`)
)

// NameValue is an environment variable or HTTP header.
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// MCPServer is a validated MCP server request. Stdio servers set Command,
// Args and Env; HTTP servers set URL and Headers.
type MCPServer struct {
	Type    string
	Name    string
	Command string
	Args    []string
	Env     []NameValue
	URL     string
	Headers []NameValue
}

// ACP returns the session/new form of s.
func (s MCPServer) ACP() any {
	if s.Type == MCPHTTP {
		headers := make([]acp.HTTPHeader, 0, len(s.Headers))
		for _, h := range s.Headers {
			headers = append(headers, acp.HTTPHeader(h))
		}
		return acp.MCPServerHTTP{Type: MCPHTTP, Name: s.Name, URL: s.URL, Headers: headers}
	}
	env := make([]acp.EnvVariable, 0, len(s.Env))
	for _, e := range s.Env {
		env = append(env, acp.EnvVariable(e))
	}
	args := append([]string{}, s.Args...)
	return acp.MCPServerStdio{Name: s.Name, Command: s.Command, Args: args, Env: env}
}

// origin describes s without any client-chosen path, query or credential:
// the command for stdio, scheme://host for HTTP.
func (s MCPServer) origin() string {
	if s.Type != MCPHTTP {
		return s.Command
	}
	u, err := url.Parse(s.URL)
	if err != nil {
		return "(invalid URL)"
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// secrets lists credential values of s that must never appear in task
// output: values of secret-looking env, header, query and option names
// (--token=V, --api-key V), and the credential part of "Scheme credential"
// header values.
func (s MCPServer) secrets() []string {
	var out []string
	for i, a := range s.Args {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name, value, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		switch {
		case !secretNameRE.MatchString(name):
		case inline:
			out = append(out, value)
		case i+1 < len(s.Args):
			out = append(out, s.Args[i+1])
		}
	}
	for _, e := range s.Env {
		if secretNameRE.MatchString(e.Name) {
			out = append(out, e.Value)
		}
	}
	for _, h := range s.Headers {
		if !secretNameRE.MatchString(h.Name) {
			continue
		}
		out = append(out, h.Value)
		if scheme, cred, ok := strings.Cut(strings.TrimSpace(h.Value), " "); ok {
			cred = strings.TrimSpace(cred)
			out = append(out, cred)
			if strings.EqualFold(scheme, "basic") {
				if raw, err := base64.StdEncoding.DecodeString(cred); err == nil {
					_, pass, _ := strings.Cut(string(raw), ":")
					out = append(out, string(raw), pass)
				}
			}
		}
	}
	if u, err := url.Parse(s.URL); err == nil {
		for _, pair := range strings.Split(u.RawQuery, "&") {
			k, v, _ := strings.Cut(pair, "=")
			name, _ := url.QueryUnescape(k)
			if v == "" || !secretNameRE.MatchString(name) {
				continue
			}
			out = append(out, v)
			if plain, err := url.QueryUnescape(v); err == nil {
				out = append(out, plain)
			}
		}
	}
	return out
}

type mcpWire struct {
	Type    *string     `json:"type"`
	Name    string      `json:"name"`
	Command *string     `json:"command"`
	Args    []string    `json:"args"`
	Env     []NameValue `json:"env"`
	URL     *string     `json:"url"`
	Headers []NameValue `json:"headers"`
}

// ParseMCPServers decodes and validates the JSON value of MetaMCPServers:
// an array of ACP McpServer objects, stdio
// {"name","command","args":[...],"env":[{"name","value"}]} or http
// {"type":"http","name","url","headers":[{"name","value"}]}. Unknown fields,
// relative commands, URLs with credentials or traversal segments, routing
// headers and well-known code-injection environment variables are refused.
// Errors never contain env, header or query values.
func ParseMCPServers(raw []byte) ([]MCPServer, error) {
	if len(raw) > maxMCPPayload {
		return nil, fmt.Errorf("%s exceeds %d bytes", MetaMCPServers, maxMCPPayload)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("%s must be an array of MCP server objects", MetaMCPServers)
	}
	if len(items) > maxMCPServers {
		return nil, fmt.Errorf("%s lists %d servers; at most %d are allowed", MetaMCPServers, len(items), maxMCPServers)
	}
	out := make([]MCPServer, 0, len(items))
	names := map[string]bool{}
	for i, item := range items {
		s, err := parseMCPServer(item)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", MetaMCPServers, i, err)
		}
		if names[s.Name] {
			return nil, fmt.Errorf("%s[%d]: duplicate server name %q", MetaMCPServers, i, s.Name)
		}
		names[s.Name] = true
		out = append(out, s)
	}
	return out, nil
}

func parseMCPServer(item json.RawMessage) (MCPServer, error) {
	var w mcpWire
	dec := json.NewDecoder(bytes.NewReader(item))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		var syn *json.SyntaxError
		var typ *json.UnmarshalTypeError
		switch {
		case errors.As(err, &typ) && typ.Field != "":
			return MCPServer{}, fmt.Errorf("field %q has the wrong type", typ.Field)
		case errors.As(err, &syn), !strings.HasPrefix(err.Error(), "json: unknown field "):
			return MCPServer{}, errors.New("not an MCP server object")
		default:
			return MCPServer{}, errors.New(strings.TrimPrefix(err.Error(), "json: "))
		}
	}
	if !mcpNameRE.MatchString(w.Name) {
		return MCPServer{}, errors.New("name must be 1-64 letters, digits, '_' or '-', starting with a letter or digit")
	}
	s := MCPServer{Name: w.Name, Type: MCPStdio}
	if w.Type != nil {
		s.Type = *w.Type
	}
	switch s.Type {
	case MCPStdio:
		if w.URL != nil || w.Headers != nil {
			return MCPServer{}, errors.New("stdio servers take command, args and env, not url or headers")
		}
		if w.Command == nil || !cleanAbsPath(*w.Command) {
			return MCPServer{}, errors.New("command must be a clean absolute path")
		}
		s.Command = *w.Command
		if len(w.Args) > maxMCPList {
			return MCPServer{}, fmt.Errorf("at most %d args are allowed", maxMCPList)
		}
		for i, a := range w.Args {
			if len(a) > maxMCPValue || strings.ContainsRune(a, 0) {
				return MCPServer{}, fmt.Errorf("args[%d] is too long or contains NUL", i)
			}
		}
		s.Args = w.Args
		env, err := nameValues("env", w.Env, func(name string) error {
			if !envNameRE.MatchString(name) {
				return errors.New("is not a valid environment variable name")
			}
			if injectionEnv(name) {
				return errors.New("can change which code the server runs and is refused")
			}
			return nil
		}, false)
		if err != nil {
			return MCPServer{}, err
		}
		s.Env = env
	case MCPHTTP:
		if w.Command != nil || w.Args != nil || w.Env != nil {
			return MCPServer{}, errors.New("http servers take url and headers, not command, args or env")
		}
		if w.URL == nil {
			return MCPServer{}, errors.New("url is required")
		}
		if _, err := parseMCPURL(*w.URL, true); err != nil {
			return MCPServer{}, err
		}
		s.URL = *w.URL
		headers, err := nameValues("headers", w.Headers, func(name string) error {
			if !headerNameRE.MatchString(name) {
				return errors.New("is not a valid HTTP header name")
			}
			if routingHeader(name) {
				return errors.New("controls routing or framing and is refused")
			}
			return nil
		}, true)
		if err != nil {
			return MCPServer{}, err
		}
		s.Headers = headers
	default:
		return MCPServer{}, errors.New(`type must be "http" or absent (stdio)`)
	}
	return s, nil
}

func nameValues(field string, in []NameValue, checkName func(string) error, foldCase bool) ([]NameValue, error) {
	if len(in) > maxMCPList {
		return nil, fmt.Errorf("at most %d %s entries are allowed", maxMCPList, field)
	}
	seen := map[string]bool{}
	out := make([]NameValue, 0, len(in))
	for i, nv := range in {
		if err := checkName(nv.Name); err != nil {
			if len(nv.Name) > 128 || !printable(nv.Name) {
				return nil, fmt.Errorf("%s[%d]: name %w", field, i, err)
			}
			return nil, fmt.Errorf("%s[%d]: %q %w", field, i, nv.Name, err)
		}
		key := nv.Name
		if foldCase {
			key = strings.ToLower(key)
		}
		if seen[key] {
			return nil, fmt.Errorf("%s[%d]: duplicate name %q", field, i, nv.Name)
		}
		seen[key] = true
		if len(nv.Value) > maxMCPValue || strings.ContainsAny(nv.Value, "\x00\r\n") {
			return nil, fmt.Errorf("%s[%d]: value of %q is too long or contains NUL, CR or LF", field, i, nv.Name)
		}
		out = append(out, nv)
	}
	return out, nil
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '�' {
			return false
		}
	}
	return true
}

func cleanAbsPath(p string) bool {
	return p != "" && len(p) <= maxMCPPath && !strings.ContainsRune(p, 0) && filepath.IsAbs(p) && filepath.Clean(p) == p
}

// injectionEnv reports variables that make a program, its interpreter, its
// shell or the tools it calls (git, ssh, npm, pagers, editors) load or run
// other code, or read configuration from elsewhere. The list is best
// effort: the operator allowlist should only name servers whose args and
// env are safe to leave to clients (CM-017).
func injectionEnv(name string) bool {
	u := strings.ToUpper(name)
	for _, prefix := range []string{"LD_", "DYLD_", "GIT_", "SSH_", "NODE_", "NPM_", "YARN_", "PNPM_", "PYTHON", "PIP_", "UV_",
		"PERL", "RUBY", "GEM_", "BUNDLE_", "JAVA_", "_JAVA_", "JDK_", "MAVEN_", "GRADLE_", "BASH_", "XDG_", "OPENSSL_", "GCONV_",
		"LESS", "CARGO_", "RUSTC", "DOTNET_", "COMPLUS_", "LUA_", "DENO_", "BUN_", "PHP", "R_PROFILE", "R_ENVIRON", "R_LIBS",
		"ERL_", "ELECTRON_", "JULIA_", "TCL", "CLASSPATH", "MONO_", "GTK_", "QT_PLUGIN", "GIO_", "GSETTINGS_"} {
		if strings.HasPrefix(u, prefix) {
			return true
		}
	}
	switch u {
	case "GOFLAGS", "GOPATH", "GOROOT", "GOENV", "GOBIN", "GOTOOLCHAIN", "GOPROXY", "GOWORK", "GOEXPERIMENT",
		"PATH", "HOME", "ENV", "ZDOTDIR", "SHELL", "SHELLOPTS", "BASHOPTS", "PS4", "IFS", "CDPATH", "PROMPT_COMMAND",
		"EDITOR", "VISUAL", "PAGER", "MANPAGER", "BROWSER", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
		"CURL_HOME", "WGETRC", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS":
		return true
	}
	return false
}

// routingHeader reports headers that select another host, path, method or
// framing than the allowlisted URL, or that the MCP client manages itself.
func routingHeader(name string) bool {
	n := strings.ToLower(name)
	for _, prefix := range []string{"proxy-", "x-forwarded-", "x-original-", "x-rewrite-", "mcp-", "sec-", "content-"} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	switch n {
	case "host", "connection", "transfer-encoding", "te", "trailer", "upgrade",
		"keep-alive", "expect", "forwarded", "via", "accept", "x-host", "x-http-method", "x-http-method-override",
		"x-method-override", "x-real-ip", "x-client-ip", "true-client-ip", "x-envoy-original-path":
		return true
	}
	return false
}

// parseMCPURL validates an http(s) URL. Request URLs may carry a query;
// allowlist prefixes may not.
func parseMCPURL(raw string, request bool) (*url.URL, error) {
	if len(raw) > maxMCPPath || strings.ContainsAny(raw, "\x00\r\n\t \\") {
		return nil, errors.New("url is too long or contains whitespace, NUL or backslash")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("url is not valid")
	}
	scheme := strings.ToLower(u.Scheme)
	switch {
	case scheme != "http" && scheme != "https":
		return nil, errors.New("url must use http or https")
	case u.Host == "" || u.Hostname() == "" || u.Opaque != "":
		return nil, errors.New("url must have a host")
	case u.User != nil:
		return nil, errors.New("url must not contain user info; send credentials in headers")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return nil, errors.New("url must not have a fragment")
	case !request && (u.RawQuery != "" || u.ForceQuery):
		return nil, errors.New("url prefix must not have a query")
	}
	if _, ok := mcpURLPath(u); !ok {
		return nil, errors.New("url path must not contain dot segments, ';' or encoded '.', '/', '\\' or ';'")
	}
	return u, nil
}

// mcpURLPath returns the escaped path ("/" when empty), refusing anything a
// server could resolve outside a matched prefix: dot segments, path
// parameters ("..;/") and encoded separators.
func mcpURLPath(u *url.URL) (string, bool) {
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	lower := strings.ToLower(p)
	if !strings.HasPrefix(p, "/") || strings.Contains(p, ";") {
		return "", false
	}
	for _, enc := range []string{"%2e", "%2f", "%5c", "%3b", "%00"} {
		if strings.Contains(lower, enc) {
			return "", false
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	return p, true
}

func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[strings.ToLower(u.Scheme)]
	}
	return strings.ToLower(u.Hostname()) + "|" + port
}

// MCPAllowlist is the operator's list of MCP servers tasks may attach.
// Each entry is an absolute command path (stdio servers must use exactly
// that command) or an http(s) URL prefix (matched on scheme, host, port and
// whole path segments), optionally bound to one server name as NAME=TARGET.
// A bare server name is refused: it would let a client run any command.
type MCPAllowlist struct {
	rules []mcpRule
}

type mcpRule struct {
	name    string
	command string
	prefix  *url.URL
	path    string // escaped prefix path
	canon   string
}

// ParseMCPAllowlist parses -mcp-allow entries; empty entries are skipped.
func ParseMCPAllowlist(entries []string) (*MCPAllowlist, error) {
	l := &MCPAllowlist{}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		var r mcpRule
		target := entry
		if name, rest, ok := strings.Cut(entry, "="); ok && mcpNameRE.MatchString(name) {
			r.name, target = name, rest
		} else if mcpNameRE.MatchString(entry) {
			return nil, fmt.Errorf("-mcp-allow entry %q: a bare server name would allow any command; use NAME=/absolute/command or NAME=https://host/prefix", entry)
		}
		lower := strings.ToLower(target)
		switch {
		case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://"):
			u, err := parseMCPURL(target, false)
			if err != nil {
				return nil, fmt.Errorf("-mcp-allow entry %q: %v", entry, err)
			}
			r.prefix = u
			r.path, _ = mcpURLPath(u)
			r.canon = strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + r.path
		case cleanAbsPath(target):
			r.command, r.canon = target, target
		default:
			return nil, fmt.Errorf("-mcp-allow entry %q: want a clean absolute command path or an http(s) URL prefix, optionally as NAME=TARGET", entry)
		}
		if r.name != "" {
			r.canon = r.name + "=" + r.canon
		}
		l.rules = append(l.rules, r)
	}
	return l, nil
}

// Empty reports whether no MCP server is allowed.
func (l *MCPAllowlist) Empty() bool { return l == nil || len(l.rules) == 0 }

// Check returns the canonical allowlist entry that permits s. The error
// names s by its command or scheme://host only, never by a client-chosen
// path or query.
func (l *MCPAllowlist) Check(s MCPServer) (string, error) {
	if l.Empty() {
		return "", errors.New("MCP servers are disabled on this gateway (configure -mcp-allow)")
	}
	var reqPath string
	var req *url.URL
	if s.Type == MCPHTTP {
		var err error
		if req, err = url.Parse(s.URL); err != nil {
			return "", errors.New("url is not valid")
		}
		var ok bool
		if reqPath, ok = mcpURLPath(req); !ok {
			return "", errors.New("url path is not allowed")
		}
	}
	for _, r := range l.rules {
		if r.name != "" && r.name != s.Name {
			continue
		}
		switch {
		case s.Type == MCPStdio && r.command != "" && r.command == s.Command:
			return r.canon, nil
		case s.Type == MCPHTTP && r.prefix != nil && strings.EqualFold(req.Scheme, r.prefix.Scheme) && hostPort(req) == hostPort(r.prefix):
			if r.path == reqPath || strings.HasPrefix(reqPath, strings.TrimSuffix(r.path, "/")+"/") {
				return r.canon, nil
			}
		}
	}
	if s.Type == MCPHTTP {
		return "", fmt.Errorf("no -mcp-allow entry covers this URL on %s", s.origin())
	}
	return "", fmt.Errorf("%s is not on the gateway's -mcp-allow list", s.origin())
}

// String lists the canonical entries, sorted, so equivalent allowlists
// compare equal.
func (l *MCPAllowlist) String() string {
	if l.Empty() {
		return ""
	}
	parts := make([]string, 0, len(l.rules))
	for _, r := range l.rules {
		parts = append(parts, r.canon)
	}
	slices.Sort(parts)
	return strings.Join(slices.Compact(parts), ",")
}
