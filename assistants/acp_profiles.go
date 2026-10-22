// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0
// Derived from the owner-approved snapshot; modified for the standalone candidate.
// See PROVENANCE.md for source and intentional behavior changes.

package assistants

import (
	"fmt"
	"slices"
	"strings"
)

// ACPProfile is a named configuration descriptor for an embedding host.
// This candidate does not mount /agents/<Name>/ or install a provider.
// Every profile runs through the same ACPExecutor, with the
// same permission relay, working-directory confinement and durable-permission
// refusal; profiles differ only in command line, environment and session meta.
type ACPProfile struct {
	Name        string
	DisplayName string
	// Command is the default agent command line.
	Command []string
	// EnvNames and EnvPrefixes extend the base environment allowlist
	// (HOME, PATH, locale, proxies, CA bundles) for this agent only.
	EnvNames    []string
	EnvPrefixes []string
	// FixedEnv entries (KEY=VALUE) are always set and win over inherited values.
	FixedEnv []string
	// ModelEnv receives the gateway's -model value; empty means -model is refused.
	ModelEnv string
	// BinaryEnv receives the gateway's -binary value; empty means -binary is refused.
	BinaryEnv string
	// SessionMeta returns the session/new _meta, or nil.
	SessionMeta func() map[string]any
}

var acpProfiles = []ACPProfile{
	{
		Name: "claude-acp", DisplayName: "Claude Code (ACP)",
		Command:     []string{"claude-agent-acp"},
		EnvPrefixes: []string{"ANTHROPIC_", "CLAUDE_CODE_USE_"},
		ModelEnv:    "ANTHROPIC_MODEL", BinaryEnv: "CLAUDE_CODE_EXECUTABLE",
		SessionMeta: ClaudeSessionMeta,
	},
	{
		Name: "codex-acp", DisplayName: "Codex (ACP)",
		Command:     []string{"codex-acp"},
		EnvPrefixes: []string{"OPENAI_", "CODEX_"},
	},
	{
		Name: "copilot-acp", DisplayName: "GitHub Copilot CLI (ACP)",
		Command:  []string{"copilot", "--acp", "--stdio"},
		EnvNames: []string{"COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GH_HOST"},
	},
	{
		Name: "gemini-acp", DisplayName: "Gemini CLI (ACP)",
		Command:     []string{"gemini", "--acp"},
		EnvPrefixes: []string{"GEMINI_", "GOOGLE_"},
		ModelEnv:    "GEMINI_MODEL",
	},
	{
		Name: "goose-acp", DisplayName: "Goose (ACP)",
		Command: []string{"goose", "acp"},
		EnvNames: []string{"OPENAI_API_KEY", "OPENAI_HOST", "ANTHROPIC_API_KEY", "ANTHROPIC_HOST",
			"GOOGLE_API_KEY", "OPENROUTER_API_KEY", "OLLAMA_HOST"},
		EnvPrefixes: []string{"GOOSE_"},
		// Goose's own mode would otherwise come from the operator's config
		// or environment; "approve" asks before every tool call.
		FixedEnv: []string{"GOOSE_MODE=approve"},
		ModelEnv: "GOOSE_MODEL",
	},
}

// ACPProfiles returns the built-in ACP agents, sorted by name.
func ACPProfiles() []ACPProfile {
	out := make([]ACPProfile, len(acpProfiles))
	for i, p := range acpProfiles {
		out[i] = p.clone()
	}
	return out
}

// ACPProfileNames returns the names of the built-in ACP agents.
func ACPProfileNames() []string {
	out := make([]string, len(acpProfiles))
	for i, p := range acpProfiles {
		out[i] = p.Name
	}
	return out
}

// LookupACPProfile finds a built-in ACP agent (case-insensitive).
func LookupACPProfile(name string) (ACPProfile, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, p := range acpProfiles {
		if p.Name == name {
			return p.clone(), true
		}
	}
	return ACPProfile{}, false
}

func (p ACPProfile) clone() ACPProfile {
	p.Command = slices.Clone(p.Command)
	p.EnvNames = slices.Clone(p.EnvNames)
	p.EnvPrefixes = slices.Clone(p.EnvPrefixes)
	p.FixedEnv = slices.Clone(p.FixedEnv)
	return p
}

// ParseEnvPassthrough parses a comma-separated list of environment variable
// names; a trailing '*' passes every variable with that prefix. A bare '*'
// is refused.
func ParseEnvPassthrough(spec string) (names, prefixes []string, err error) {
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, isPrefix := strings.CutSuffix(item, "*")
		if !envNameRE.MatchString(name) {
			return nil, nil, fmt.Errorf("invalid environment variable name or prefix %q", item)
		}
		if isPrefix {
			prefixes = append(prefixes, name)
		} else {
			names = append(names, name)
		}
	}
	return names, prefixes, nil
}
