// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"
)

// All provider-shaped strings are generated synthetic patterns, never issued
// credentials. No service is contacted and no private key material is used.
func TestSyntheticPatternsAndLiterals(t *testing.T) {
	for _, synthetic := range []string{
		"gh" + "p_" + strings.Repeat("T", 30),
		"glpat-" + strings.Repeat("T", 25),
		"AKIA" + strings.Repeat("Z", 16),
		"sk-" + strings.Repeat("T", 32),
		"-----BEGIN PRIVATE KEY-----\nSYNTHETIC-NOT-A-KEY\n-----END PRIVATE KEY-----",
		"password=synthetic-password",
	} {
		out := String(synthetic)
		if out == synthetic || !strings.Contains(out, Mask) {
			t.Fatalf("synthetic pattern was not masked: %q", out)
		}
	}
	if got := New("synthetic-literal-value").String("prefix synthetic-literal-value suffix"); got != "prefix "+Mask+" suffix" {
		t.Fatal(got)
	}
}

func TestStreamMasksEverySplitIncludingPatternOnly(t *testing.T) {
	token := "gh" + "p_" + strings.Repeat("T", 30)
	for _, r := range []*Redactor{nil, New(token), New("different-synthetic-value")} {
		for split := 0; split <= len(token); split++ {
			stream := r.Stream()
			out := stream.Write("before " + token[:split])
			out += stream.Write(token[split:] + " after")
			out += stream.Flush()
			if out != "before "+Mask+" after" {
				t.Fatalf("split %d leaked or damaged text: %q", split, out)
			}
		}
	}
}

func TestStreamBoundAndUnicode(t *testing.T) {
	stream := New().Stream()
	if out := stream.Write(strings.Repeat("x", MaxStreamBytes+1)); out != "" {
		t.Fatal("oversized content emitted")
	}
	if out := stream.Flush(); !strings.Contains(out, "exceeded limit") {
		t.Fatal(out)
	}
	stream.Write("a界")
	stream.Write("b")
	if out := stream.Flush(); out != "a界b" {
		t.Fatal(out)
	}
}

func TestPerTaskLiteralsDoNotMutateBase(t *testing.T) {
	base := New("global-synthetic-value")
	a := base.With("tenant-a-synthetic-value")
	b := base.With("tenant-b-synthetic-value")
	if base.String("tenant-a-synthetic-value") != "tenant-a-synthetic-value" ||
		b.String("tenant-a-synthetic-value") != "tenant-a-synthetic-value" ||
		a.String("tenant-a-synthetic-value") != Mask {
		t.Fatal("task redaction isolation failed")
	}
}

func TestKnownShortCredentialsAreNotIgnored(t *testing.T) {
	base := New()
	for _, value := range []string{"X", "X!3", "X!3-short"} {
		strict := base.WithSecrets(value)
		if strict.String("before "+value+" after") != "before "+Mask+" after" {
			t.Fatalf("known short credential not redacted")
		}
		if base.String(value) != value {
			t.Fatal("base redactor mutated")
		}
	}
}

func TestShortLiteralsDoNotRecursivelyExpandMasks(t *testing.T) {
	r := New().WithSecrets("A", "C", "D", "E", "R", "T")
	if got := r.String("A E"); got != Mask+" "+Mask {
		t.Fatalf("replacement cascaded into inserted masks: %q", got)
	}
	if got := r.With("another-synthetic-literal").String("A"); got != Mask {
		t.Fatal("With dropped an existing strict short credential")
	}
}
