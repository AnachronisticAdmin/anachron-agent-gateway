// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0
// Derived from the owner-approved snapshot; modified for the standalone candidate.
// See PROVENANCE.md for source and intentional behavior changes.

package assistants

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/redact"
)

const testSecret = "s3cr3t-value-never-logged"

func TestParseMCPServers(t *testing.T) {
	valid := []struct {
		name string
		in   string
		want []MCPServer
	}{
		{"null", `null`, []MCPServer{}},
		{"empty", `[]`, []MCPServer{}},
		{"stdio minimal", `[{"name":"git","command":"/opt/mcp/git"}]`,
			[]MCPServer{{Type: MCPStdio, Name: "git", Command: "/opt/mcp/git", Env: []NameValue{}}}},
		{"stdio explicit type", `[{"type":"stdio","name":"git","command":"/opt/mcp/git","args":["--repo","."],"env":[{"name":"REPO_TOKEN","value":"x"}]}]`,
			[]MCPServer{{Type: MCPStdio, Name: "git", Command: "/opt/mcp/git", Args: []string{"--repo", "."}, Env: []NameValue{{"REPO_TOKEN", "x"}}}}},
		{"http", `[{"type":"http","name":"jira","url":"https://mcp.example.com/jira?team=a","headers":[{"name":"Authorization","value":"Bearer t"}]}]`,
			[]MCPServer{{Type: MCPHTTP, Name: "jira", URL: "https://mcp.example.com/jira?team=a", Headers: []NameValue{{"Authorization", "Bearer t"}}}}},
		{"both", `[{"name":"a","command":"/a","args":[],"env":[]},{"type":"http","name":"b","url":"http://127.0.0.1:9000/mcp","headers":[]}]`,
			[]MCPServer{{Type: MCPStdio, Name: "a", Command: "/a", Args: []string{}, Env: []NameValue{}},
				{Type: MCPHTTP, Name: "b", URL: "http://127.0.0.1:9000/mcp", Headers: []NameValue{}}}},
	}
	for _, tc := range valid {
		got, err := ParseMCPServers([]byte(tc.in))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %#v\nwant %#v", tc.name, got, tc.want)
		}
	}

	many := "[" + strings.Repeat(`{"name":"x","command":"/x"},`, maxMCPServers) + `{"name":"y","command":"/y"}]`
	invalid := []struct {
		name, in, want string
	}{
		{"not array", `{"name":"git"}`, "must be an array"},
		{"not json", `[{`, "must be an array"},
		{"too many", many, "at most 16"},
		{"too large", `["` + strings.Repeat("a", maxMCPPayload) + `"]`, "exceeds"},
		{"not object", `["git"]`, "not an MCP server object"},
		{"unknown field", `[{"name":"git","command":"/g","cwd":"/tmp"}]`, `unknown field "cwd"`},
		{"meta field", `[{"name":"git","command":"/g","_meta":{}}]`, `unknown field "_meta"`},
		{"wrong type", `[{"name":"git","command":"/g","args":"--x"}]`, `"args" has the wrong type`},
		{"missing name", `[{"command":"/g"}]`, "name must be"},
		{"bad name", `[{"name":"../git","command":"/g"}]`, "name must be"},
		{"long name", `[{"name":"` + strings.Repeat("a", 65) + `","command":"/g"}]`, "name must be"},
		{"duplicate", `[{"name":"git","command":"/g"},{"name":"git","command":"/h"}]`, "duplicate server name"},
		{"sse", `[{"type":"sse","name":"s","url":"https://h/"}]`, `type must be "http"`},
		{"missing command", `[{"name":"git"}]`, "clean absolute path"},
		{"relative command", `[{"name":"git","command":"npx"}]`, "clean absolute path"},
		{"unclean command", `[{"name":"git","command":"/opt/../bin/sh"}]`, "clean absolute path"},
		{"stdio with url", `[{"name":"git","command":"/g","url":"https://h/"}]`, "not url or headers"},
		{"NUL arg", `[{"name":"git","command":"/g","args":["a\u0000b"]}]`, "contains NUL"},
		{"bad env name", `[{"name":"git","command":"/g","env":[{"name":"1BAD","value":"` + testSecret + `"}]}]`, "not a valid environment variable name"},
		{"injection env", `[{"name":"git","command":"/g","env":[{"name":"DYLD_INSERT_LIBRARIES","value":"` + testSecret + `"}]}]`, "change which code"},
		{"node options", `[{"name":"git","command":"/g","env":[{"name":"NODE_OPTIONS","value":"` + testSecret + `"}]}]`, "change which code"},
		{"path env", `[{"name":"git","command":"/g","env":[{"name":"PATH","value":"/tmp"}]}]`, "change which code"},
		{"git hook env", `[{"name":"git","command":"/g","env":[{"name":"GIT_EXTERNAL_DIFF","value":"sh -c x"}]}]`, "change which code"},
		{"git template env", `[{"name":"git","command":"/g","env":[{"name":"git_template_dir","value":"/tmp/t"}]}]`, "change which code"},
		{"home env", `[{"name":"git","command":"/g","env":[{"name":"HOME","value":"/tmp/h"}]}]`, "change which code"},
		{"host header", `[{"type":"http","name":"j","url":"https://h/","headers":[{"name":"Host","value":"admin.internal"}]}]`, "routing"},
		{"rewrite header", `[{"type":"http","name":"j","url":"https://h/","headers":[{"name":"X-Original-URL","value":"/admin"}]}]`, "routing"},
		{"forwarded header", `[{"type":"http","name":"j","url":"https://h/","headers":[{"name":"x-forwarded-host","value":"a"}]}]`, "routing"},
		{"session header", `[{"type":"http","name":"j","url":"https://h/","headers":[{"name":"Mcp-Session-Id","value":"a"}]}]`, "routing"},
		{"path parameter", `[{"type":"http","name":"j","url":"https://h/mcp/..;/admin"}]`, "';'"},
		{"duplicate env", `[{"name":"git","command":"/g","env":[{"name":"A","value":"1"},{"name":"A","value":"2"}]}]`, "duplicate name"},
		{"newline env value", `[{"name":"git","command":"/g","env":[{"name":"A","value":"` + testSecret + `\nB=1"}]}]`, "contains NUL, CR or LF"},
		{"http without url", `[{"type":"http","name":"j"}]`, "url is required"},
		{"http with command", `[{"type":"http","name":"j","url":"https://h/","command":"/g"}]`, "not command"},
		{"ftp url", `[{"type":"http","name":"j","url":"ftp://h/"}]`, "http or https"},
		{"no host", `[{"type":"http","name":"j","url":"https:///mcp"}]`, "must have a host"},
		{"user info", `[{"type":"http","name":"j","url":"https://user:` + testSecret + `@h/"}]`, "user info"},
		{"fragment", `[{"type":"http","name":"j","url":"https://h/#x"}]`, "fragment"},
		{"dot segment", `[{"type":"http","name":"j","url":"https://h/mcp/../admin"}]`, "dot segments"},
		{"encoded dot", `[{"type":"http","name":"j","url":"https://h/mcp/%2e%2e/admin"}]`, "dot segments"},
		{"encoded slash", `[{"type":"http","name":"j","url":"https://h/mcp%2F..%2Fadmin"}]`, "dot segments"},
		{"bad header", `[{"type":"http","name":"j","url":"https://h/","headers":[{"name":"Bad Header","value":"` + testSecret + `"}]}]`, "not a valid HTTP header name"},
		{"duplicate header", `[{"type":"http","name":"j","url":"https://h/","headers":[{"name":"X-A","value":"1"},{"name":"x-a","value":"2"}]}]`, "duplicate name"},
		{"CRLF header value", `[{"type":"http","name":"j","url":"https://h/","headers":[{"name":"X-A","value":"` + testSecret + `\r\nX-B: 1"}]}]`, "contains NUL, CR or LF"},
	}
	for _, tc := range invalid {
		_, err := ParseMCPServers([]byte(tc.in))
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.want)
		}
		if strings.Contains(err.Error(), testSecret) {
			t.Errorf("%s: error leaks a credential value: %q", tc.name, err)
		}
	}
}

func TestMCPServerACPForm(t *testing.T) {
	servers, err := ParseMCPServers([]byte(`[{"name":"git","command":"/opt/mcp/git"},
		{"type":"http","name":"jira","url":"https://mcp.example.com/jira?token=` + testSecret + `"}]`))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range servers {
		b, _ := json.Marshal(s.ACP())
		got = append(got, string(b))
	}
	want := []string{
		`{"name":"git","command":"/opt/mcp/git","args":[],"env":[]}`,
		`{"type":"http","name":"jira","url":"https://mcp.example.com/jira?token=` + testSecret + `","headers":[]}`,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ACP form:\n got %v\nwant %v", got, want)
	}
	if origin := servers[1].origin(); origin != "https://mcp.example.com" {
		t.Fatalf("origin must drop path and query: %q", origin)
	}
	if !slices.Contains(servers[1].secrets(), testSecret) {
		t.Fatal("URL query values of secret-looking names must be masked in task output")
	}
}

func TestMCPServerSecretsAreSelectedByName(t *testing.T) {
	basic := "dXNlcjpiYXNpYy1wYXNzd29yZC0x" // user:basic-password-1
	servers, err := ParseMCPServers([]byte(`[{"name":"git","command":"/opt/mcp/git",
		"args":["--repo","/Users/someone/repo","--token=arg-token-inline-1","--api-key","arg-token-separate-1"],"env":[
		{"name":"REPO_TOKEN","value":"env-token-value-1"},{"name":"REPO_ROOT","value":"/Users/someone/project"}]},
		{"type":"http","name":"jira","url":"https://h/mcp?api_key=query%2Bkey-1&team=engineering","headers":[
		{"name":"Authorization","value":"Bearer bearer-token-value-1"},{"name":"X-Trace","value":"trace-header-value"}]},
		{"type":"http","name":"b","url":"https://h/mcp","headers":[{"name":"Authorization","value":"Basic ` + basic + `"}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range servers {
		got = append(got, s.secrets()...)
	}
	for _, want := range []string{"env-token-value-1", "Bearer bearer-token-value-1", "bearer-token-value-1", "query%2Bkey-1", "query+key-1", basic,
		"basic-password-1", "arg-token-inline-1", "arg-token-separate-1"} {
		if !slices.Contains(got, want) {
			t.Errorf("%q is not masked", want)
		}
	}
	for _, plain := range []string{"/Users/someone/project", "/Users/someone/repo", "engineering", "trace-header-value"} {
		if slices.Contains(got, plain) {
			t.Errorf("%q is not a credential and must stay readable for the approver", plain)
		}
	}
}

func TestRedactedJSONMasksEscapedLiterals(t *testing.T) {
	secret := `p"ss\w0rd<&>-credential`
	red := redact.New(secret)
	raw, _ := json.Marshal(map[string]any{"command": "login --password='" + secret + "'", secret: []any{secret}})
	if strings.Contains(string(raw), secret) {
		t.Fatal("test setup: the JSON text should hide the literal behind escapes")
	}
	out, _ := json.Marshal(redactedJSON(raw, red))
	var decoded any
	_ = json.Unmarshal(out, &decoded)
	if flat, _ := json.Marshal(decoded); strings.Contains(string(out), "w0rd") || strings.Contains(string(flat), "w0rd") {
		t.Fatalf("escaped literal survived: %s", out)
	}
}

func TestParseMCPAllowlist(t *testing.T) {
	l, err := ParseMCPAllowlist([]string{" /opt/mcp/git ", "", "jira=https://MCP.example.com/jira/", "local=http://127.0.0.1:9000"})
	if err != nil {
		t.Fatal(err)
	}
	if got := l.String(); got != "/opt/mcp/git,jira=https://mcp.example.com/jira/,local=http://127.0.0.1:9000/" {
		t.Fatalf("canonical form: %s", got)
	}
	reordered, _ := ParseMCPAllowlist([]string{"local=http://127.0.0.1:9000/", "jira=https://mcp.EXAMPLE.com/jira/", "/opt/mcp/git", "/opt/mcp/git"})
	if reordered.String() != l.String() {
		t.Fatalf("equivalent allowlists must have one canonical form: %s", reordered)
	}
	if empty, _ := ParseMCPAllowlist(nil); !empty.Empty() {
		t.Fatal("no entries must mean empty")
	} else if _, err := empty.Check(MCPServer{Type: MCPStdio, Name: "g", Command: "/g"}); err == nil {
		t.Fatal("an empty allowlist must refuse every server")
	}
	for _, bad := range []string{"git", "relative/cmd", "git=npx", "/opt/../bin/sh", "ftp://h/", "https://h/x?y=1", "https://h/#f",
		"https://u:p@h/", "https://h/a/../b", "https://h/a/..;/b", "=https://h/", "bad name=/x"} {
		if _, err := ParseMCPAllowlist([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParseMCPAllowlist([]string{"git"}); err == nil || !strings.Contains(err.Error(), "bare server name") {
		t.Fatalf("bare names must be explained: %v", err)
	}
}

func TestMCPAllowlistCheck(t *testing.T) {
	l, err := ParseMCPAllowlist([]string{"/opt/mcp/fs", "git=/opt/mcp/git", "https://mcp.example.com/tools/", "jira=https://jira.example.com:8443/mcp", "http://127.0.0.1:9000"})
	if err != nil {
		t.Fatal(err)
	}
	stdio := func(name, cmd string) MCPServer { return MCPServer{Type: MCPStdio, Name: name, Command: cmd} }
	http := func(name, u string) MCPServer { return MCPServer{Type: MCPHTTP, Name: name, URL: u} }
	cases := []struct {
		s  MCPServer
		ok bool
	}{
		{stdio("anything", "/opt/mcp/fs"), true},
		{stdio("git", "/opt/mcp/git"), true},
		{stdio("other", "/opt/mcp/git"), false}, // command bound to the name git
		{stdio("git", "/opt/mcp/git2"), false},
		{stdio("fs", "/opt/mcp"), false},
		{http("t", "https://mcp.example.com/tools/a"), true},
		{http("t", "https://MCP.EXAMPLE.COM:443/tools/a?x=1"), true},
		{http("t", "https://mcp.example.com/tools/"), true},
		{http("t", "https://mcp.example.com/tools"), false},
		{http("t", "https://mcp.example.com/toolsx/a"), false},
		{http("t", "http://mcp.example.com/tools/a"), false},
		{http("t", "https://mcp.example.com.evil.net/tools/a"), false},
		{http("t", "https://mcp.example.com:8443/tools/a"), false},
		{http("jira", "https://jira.example.com:8443/mcp"), true},
		{http("jira", "https://jira.example.com:8443/mcp/v1"), true},
		{http("jira", "https://jira.example.com:8443/mcpx"), false},
		{http("other", "https://jira.example.com:8443/mcp"), false},
		{http("l", "http://127.0.0.1:9000/anything"), true},
		{http("l", "http://127.0.0.1:9001/"), false},
		{http("t", "https://mcp.example.com/tools/../admin"), false},
		{http("t", "https://mcp.example.com/tools/..;/admin"), false},
		{http("t", "https://mcp.example.com/tools/a;jsessionid=1"), false},
		{stdio("x", "https://mcp.example.com/tools/a"), false},
		{http("x", "/opt/mcp/fs"), false},
	}
	for _, tc := range cases {
		allowedBy, err := l.Check(tc.s)
		if (err == nil) != tc.ok {
			t.Errorf("%s %s %s%s: allowed=%v (%v)", tc.s.Type, tc.s.Name, tc.s.Command, tc.s.URL, err == nil, err)
		}
		if err == nil && allowedBy == "" {
			t.Errorf("%s: no matching entry reported", tc.s.Name)
		}
	}
	if by, _ := l.Check(http("jira", "https://jira.example.com:8443/mcp/T0/secret-path-token")); by != "jira=https://jira.example.com:8443/mcp" {
		t.Fatalf("allowedBy must be the operator's entry, not the client's URL: %q", by)
	}
	if _, err := l.Check(http("t", "https://mcp.example.com/other/secret-path-token")); err == nil || strings.Contains(err.Error(), "secret-path-token") {
		t.Fatalf("refusals must not echo the client's path: %v", err)
	}
}

func TestParseEnvPassthrough(t *testing.T) {
	names, prefixes, err := ParseEnvPassthrough(" FOO_TOKEN, AWS_*,,BAR ")
	if err != nil || !slices.Equal(names, []string{"FOO_TOKEN", "BAR"}) || !slices.Equal(prefixes, []string{"AWS_"}) {
		t.Fatalf("%v %v %v", names, prefixes, err)
	}
	for _, bad := range []string{"*", "A B", "1X", "X=1", "A**"} {
		if _, _, err := ParseEnvPassthrough(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestACPProfiles(t *testing.T) {
	want := map[string][]string{
		"claude-acp":  {"claude-agent-acp"},
		"codex-acp":   {"codex-acp"},
		"copilot-acp": {"copilot", "--acp", "--stdio"},
		"gemini-acp":  {"gemini", "--acp"},
		"goose-acp":   {"goose", "acp"},
	}
	if got := ACPProfileNames(); !slices.Equal(got, []string{"claude-acp", "codex-acp", "copilot-acp", "gemini-acp", "goose-acp"}) {
		t.Fatalf("profiles: %v", got)
	}
	for _, p := range ACPProfiles() {
		if !slices.Equal(p.Command, want[p.Name]) {
			t.Errorf("%s default command %v", p.Name, p.Command)
		}
		claude := p.Name == "claude-acp"
		if (p.SessionMeta != nil) != claude || (p.BinaryEnv != "") != claude ||
			slices.ContainsFunc(p.EnvPrefixes, func(s string) bool { return s == "ANTHROPIC_" }) != claude {
			t.Errorf("%s: Claude-only meta, binary and ANTHROPIC_ passthrough must apply to claude-acp alone", p.Name)
		}
		if found, ok := LookupACPProfile(p.Name); !ok || found.Name != p.Name {
			t.Errorf("%s cannot be found in the standalone profile registry", p.Name)
		}
	}
	goose, _ := LookupACPProfile("GOOSE-ACP")
	if !slices.Contains(goose.FixedEnv, "GOOSE_MODE=approve") {
		t.Fatal("goose-acp must pin approval mode")
	}
	goose.Command[0] = "mutated"
	if again, _ := LookupACPProfile("goose-acp"); again.Command[0] != "goose" {
		t.Fatal("profiles must be returned as copies")
	}
	if _, ok := LookupACPProfile("acp"); ok {
		t.Fatal("unknown profile found")
	}
}

func TestAgentEnvAllowlist(t *testing.T) {
	t.Setenv("ACP_TEST_KEEP", "1")
	t.Setenv("ACP_TEST_PREFIX_ONE", "1")
	t.Setenv("ACP_TEST_DROP", "1")
	t.Setenv("GOOSE_MODE", "auto")
	env := agentEnv([]string{"ACP_TEST_KEEP"}, []string{"ACP_TEST_PREFIX_", "GOOSE_", ""}, []string{"GOOSE_MODE=approve"})
	count := func(key string) (n int, last string) {
		for _, kv := range env {
			if k, v, _ := strings.Cut(kv, "="); k == key {
				n, last = n+1, v
			}
		}
		return
	}
	if n, _ := count("ACP_TEST_KEEP"); n != 1 {
		t.Error("named variable not passed")
	}
	if n, _ := count("ACP_TEST_PREFIX_ONE"); n != 1 {
		t.Error("prefixed variable not passed")
	}
	if n, _ := count("ACP_TEST_DROP"); n != 0 {
		t.Error("unlisted variable passed")
	}
	if n, v := count("GOOSE_MODE"); n != 1 || v != "approve" {
		t.Errorf("fixed variable must replace the inherited one: %d %q", n, v)
	}
	if n, v := count("TERM"); n != 1 || v != "dumb" {
		t.Errorf("TERM: %d %q", n, v)
	}
	if n, _ := count("HOME"); n != 1 && os.Getenv("HOME") != "" {
		t.Error("base allowlist missing")
	}
}

func FuzzMCPServers(f *testing.F) {
	f.Add([]byte(`[{"name":"git","command":"/opt/mcp/git","args":["-v"],"env":[{"name":"T","value":"x"}]}]`))
	f.Add([]byte(`[{"type":"http","name":"j","url":"https://mcp.example.com/tools/a?x=1","headers":[{"name":"Authorization","value":"Bearer t"}]}]`))
	f.Add([]byte(`[{"type":"http","name":"j","url":"https://h/%2e%2e/"}]`))
	f.Add([]byte(`null`))
	allow, err := ParseMCPAllowlist([]string{"/opt/mcp/git", "j=https://mcp.example.com/tools/"})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		servers, err := ParseMCPServers(raw)
		if err != nil {
			return
		}
		for i, s := range servers {
			if !mcpNameRE.MatchString(s.Name) {
				t.Fatalf("invalid name accepted: %q", s.Name)
			}
			if s.Type == MCPStdio && !cleanAbsPath(s.Command) {
				t.Fatalf("invalid command accepted: %q", s.Command)
			}
			if s.Type == MCPHTTP {
				if _, err := parseMCPURL(s.URL, true); err != nil {
					t.Fatalf("invalid url accepted: %q", s.URL)
				}
			}
			_, _ = allow.Check(s)
			_ = s.secrets()
			// What is accepted must survive the trip to session/new and back
			// unchanged. Items are re-parsed one by one: re-encoding can grow
			// a payload (escaped U+2028, replaced invalid UTF-8) past the limit.
			b, err := json.Marshal(s.ACP())
			if err != nil {
				t.Fatal(err)
			}
			again, err := parseMCPServer(b)
			if err != nil {
				t.Fatalf("ACP form of server %d rejected: %v\n%s", i, err, b)
			}
			if again.Type != s.Type || again.Name != s.Name || again.Command != s.Command || again.URL != s.URL ||
				len(again.Args) != len(s.Args) || len(again.Env) != len(s.Env) || len(again.Headers) != len(s.Headers) {
				t.Fatalf("round trip changed server %d: %#v vs %#v", i, again, s)
			}
		}
	})
}
