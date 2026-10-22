// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0
// Derived from the owner-approved snapshot; modified for the standalone candidate.
// See PROVENANCE.md for source and intentional behavior changes.

// Package redact removes credentials and secrets from text before it is
// stored in task state, logged or returned to A2A clients.
package redact

import (
	"regexp"
	"sort"
	"strings"
)

// Mask replaces redacted values.
const Mask = "[REDACTED]"

type rule struct {
	re   *regexp.Regexp
	repl string
}

var rules = []rule{
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), Mask},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), Mask},
	{regexp.MustCompile(`\bsk-(?:ant-|proj-|svcacct-)?[A-Za-z0-9_\-]{16,}`), Mask},
	{regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})`), Mask},
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}`), Mask},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), Mask},
	{regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`), Mask},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}`), Mask},
	{regexp.MustCompile(`\bapk_[A-Za-z0-9_\-]{16,}`), Mask},
	{regexp.MustCompile(`(?i)\b(bearer|basic|token)(\s+)[A-Za-z0-9._~+/=\-]{8,}`), "${1}${2}" + Mask},
	{regexp.MustCompile(`(?i)\b((?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password|passwd|private[_-]?key|client[_-]?secret)["']?\s*[=:]\s*["']?)[^\s"',;&]{4,}`), "${1}" + Mask},
	{regexp.MustCompile(`(?i)(://[^/\s:@]+:)[^/\s@]+@`), "${1}" + Mask + "@"},
}

// String redacts well-known secret formats from s.
func String(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// Redactor additionally masks configured literal values, such as the values
// of credential environment variables passed to a subprocess.
type Redactor struct {
	literals []string
	replacer *strings.Replacer
}

// New returns a Redactor masking the given literal values. Values shorter
// than 8 bytes are ignored to avoid masking common words.
func New(literals ...string) *Redactor {
	r := &Redactor{}
	seen := map[string]bool{}
	for _, l := range literals {
		l = strings.TrimSpace(l)
		if len(l) >= 8 && !seen[l] {
			seen[l] = true
			r.literals = append(r.literals, l)
		}
	}
	sort.Slice(r.literals, func(i, j int) bool { return len(r.literals[i]) > len(r.literals[j]) })
	r.prepare()
	return r
}

func (r *Redactor) prepare() {
	pairs := make([]string, 0, 2*len(r.literals))
	for _, value := range r.literals {
		pairs = append(pairs, value, Mask)
	}
	r.replacer = strings.NewReplacer(pairs...)
}

// With returns a Redactor that masks r's literals and the given ones, for
// example per-task credentials. r is not modified; a nil r is allowed.
func (r *Redactor) With(literals ...string) *Redactor {
	if len(literals) == 0 {
		return r
	}
	added := New(literals...)
	return r.WithSecrets(added.literals...)
}

// WithSecrets masks every nonempty known credential, including short values.
// Unlike New/With, this security-sensitive path does not apply the eight-byte
// convenience threshold. Very short credentials may substantially redact text.
func (r *Redactor) WithSecrets(values ...string) *Redactor {
	out := &Redactor{}
	seen := map[string]bool{}
	add := func(value string) {
		if value != "" && !seen[value] {
			seen[value] = true
			out.literals = append(out.literals, value)
		}
	}
	if r != nil {
		for _, value := range r.literals {
			add(value)
		}
	}
	for _, value := range values {
		add(value)
	}
	sort.Slice(out.literals, func(i, j int) bool { return len(out.literals[i]) > len(out.literals[j]) })
	out.prepare()
	return out
}

// String redacts literals and well-known secret formats.
func (r *Redactor) String(s string) string {
	if r != nil && r.replacer != nil {
		// One pass avoids repeatedly replacing characters inside the inserted
		// mask when several very short known credentials overlap it.
		s = r.replacer.Replace(s)
	}
	return String(s)
}

// Stream conservatively buffers a bounded segment before redacting it.
// This also masks pattern-only credentials split across arbitrary chunks.
// It intentionally does not promise token-by-token live output.
type Stream struct {
	r        *Redactor
	pending  string
	overflow bool
}

// Stream returns a streaming redactor for r; a nil r is allowed.
func (r *Redactor) Stream() *Stream {
	return &Stream{r: r}
}

// MaxStreamBytes bounds one segment between Flush calls.
const MaxStreamBytes = 64 << 10

// Write emits no text before Flush. An oversized segment is withheld in full.
func (s *Stream) Write(piece string) string {
	if s.overflow {
		return ""
	}
	if len(piece) > MaxStreamBytes-len(s.pending) {
		s.pending, s.overflow = "", true
		return ""
	}
	s.pending += piece
	return ""
}

// Flush redacts the complete segment or returns a non-content overflow marker.
func (s *Stream) Flush() string {
	if s.overflow {
		s.overflow = false
		return Mask + " [stream segment exceeded limit]"
	}
	out := s.pending
	s.pending = ""
	if out == "" {
		return ""
	}
	return s.r.String(out)
}
