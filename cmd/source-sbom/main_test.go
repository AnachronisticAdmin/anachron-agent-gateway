// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"testing"
)

const inventory = "sbom.source.spdx.json"

func fixture(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	write(t, "go.mod", []byte("module "+modulePath+"\n\ngo 1.26.0\n"))
	write(t, "README.md", []byte("Synthetic inventory test fixture.\n"))
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryRoundTripAndMetadataTampering(t *testing.T) {
	fixture(t)
	if err := run(inventory, ""); err != nil {
		t.Fatal(err)
	}
	if err := run(inventory, inventory); err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(inventory)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*document){
		"package-name": func(d *document) { d.Packages[0]["name"] = "example.invalid/other" },
		"version":      func(d *document) { d.Packages[0]["versionInfo"] = "unreviewed" },
		"toolchain":    func(d *document) { d.Packages[1]["versionInfo"] = "go0.0.0" },
		"license":      func(d *document) { d.Packages[0]["licenseDeclared"] = "NOASSERTION" },
		"verification": func(d *document) {
			d.Packages[0]["packageVerificationCode"] = map[string]any{"packageVerificationCodeValue": "invalid"}
		},
		"relationships": func(d *document) { d.Relationships = nil },
		"file-license":  func(d *document) { d.Files[0].LicenseInFiles = []string{"NOASSERTION"} },
		"namespace":     func(d *document) { d.Namespace = "urn:sha256:invalid" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var saved document
			if err := json.Unmarshal(baseline, &saved); err != nil {
				t.Fatal(err)
			}
			mutate(&saved)
			data, err := json.Marshal(saved)
			if err != nil {
				t.Fatal(err)
			}
			write(t, inventory, data)
			if err := run(inventory, inventory); err == nil {
				t.Fatal("tampered inventory unexpectedly verified")
			}
		})
	}
}

func TestInventoryDetectsChangesAndExtraFiles(t *testing.T) {
	fixture(t)
	if err := run(inventory, ""); err != nil {
		t.Fatal(err)
	}
	write(t, "README.md", []byte("Changed synthetic fixture.\n"))
	if err := run(inventory, inventory); err == nil {
		t.Fatal("changed file unexpectedly verified")
	}
	if err := run(inventory, ""); err != nil {
		t.Fatal(err)
	}
	write(t, "unexpected.txt", []byte("Extra synthetic fixture.\n"))
	if err := run(inventory, inventory); err == nil {
		t.Fatal("unrecorded file unexpectedly verified")
	}
}

func TestInventoryRejectsTrailingOrUnknownJSON(t *testing.T) {
	fixture(t)
	if err := run(inventory, ""); err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(inventory)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(baseline, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpectedField"] = "synthetic fixture"
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"trailing-document": append(append([]byte(nil), baseline...), []byte("{}")...),
		"unknown-field":     unknown,
	} {
		t.Run(name, func(t *testing.T) {
			write(t, inventory, data)
			if err := run(inventory, inventory); err == nil {
				t.Fatal("unreviewed JSON unexpectedly verified")
			}
		})
	}
}

func TestInventoryRejectsForeignModule(t *testing.T) {
	fixture(t)
	write(t, "go.mod", []byte("module example.invalid/other\n\ngo 1.26.0\n"))
	if err := run(inventory, ""); err == nil {
		t.Fatal("unexpected module accepted")
	}
}

func TestInventoryRejectsSymlink(t *testing.T) {
	fixture(t)
	if err := os.Symlink("README.md", "linked-fixture"); err != nil {
		t.Skip("symlinks unavailable on this platform")
	}
	if err := run(inventory, ""); err == nil {
		t.Fatal("symlink accepted")
	}
}
