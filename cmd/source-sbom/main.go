// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

// Command source-sbom inventories this directory only. It is not a binary
// composition, vulnerability, legal-clearance or private-parent scan.
package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"
)

const modulePath = "github.com/AnachronisticAdmin/anachron-agent-gateway"
const inventoryName = "Anachron Agent Gateway source inventory"
const sourceVersion = "0.1.0-alpha.1-dev"

type checksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}
type sourceFile struct {
	ID             string     `json:"SPDXID"`
	Name           string     `json:"fileName"`
	Checksums      []checksum `json:"checksums"`
	License        string     `json:"licenseConcluded"`
	LicenseInFiles []string   `json:"licenseInfoInFiles"`
	Copyright      string     `json:"copyrightText"`
}
type document struct {
	Version       string              `json:"spdxVersion"`
	DataLicense   string              `json:"dataLicense"`
	ID            string              `json:"SPDXID"`
	Name          string              `json:"name"`
	Namespace     string              `json:"documentNamespace"`
	Creation      map[string]any      `json:"creationInfo"`
	Comment       string              `json:"comment"`
	Packages      []map[string]any    `json:"packages"`
	Files         []sourceFile        `json:"files"`
	Relationships []map[string]string `json:"relationships"`
}

func main() {
	out := flag.String("out", "sbom.source.spdx.json", "source inventory output")
	check := flag.String("check", "", "verify an existing source inventory")
	flag.Parse()
	if err := run(*out, *check); err != nil {
		fmt.Fprintln(os.Stderr, "source SBOM:", err)
		os.Exit(1)
	}
}

func run(out, check string) error {
	raw, err := exec.Command("go", "list", "-m", "-json", "all").Output()
	if err != nil {
		return errors.New("cannot inspect the independent Go module graph")
	}
	var module struct{ Path, GoVersion string }
	if err := json.Unmarshal(raw, &module); err != nil || module.Path != modulePath {
		return errors.New("expected exactly one independent module and no external dependencies")
	}
	var files []sourceFile
	err = filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch path {
			case ".git", "validation", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if path == "sbom.source.spdx.json" || path == out {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular source entry refused: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		h256, h1 := sha256.Sum256(data), sha1.Sum(data)
		nameHash := sha1.Sum([]byte(filepath.ToSlash(path)))
		license := "Apache-2.0"
		if filepath.ToSlash(path) == "third_party/GO-LICENSE" {
			license = "BSD-3-Clause"
		}
		files = append(files, sourceFile{
			ID: "SPDXRef-File-" + hex.EncodeToString(nameHash[:]), Name: "./" + filepath.ToSlash(path),
			Checksums: []checksum{{"SHA256", hex.EncodeToString(h256[:])}, {"SHA1", hex.EncodeToString(h1[:])}},
			License:   "NOASSERTION", LicenseInFiles: []string{license}, Copyright: "NOASSERTION",
		})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	var hashes []string
	for _, file := range files {
		hashes = append(hashes, file.Checksums[1].Value)
	}
	sort.Strings(hashes)
	verification := sha1.Sum([]byte(strings.Join(hashes, "")))
	created := time.Now().UTC().Format(time.RFC3339)
	var saved document
	if check != "" {
		data, err := os.ReadFile(check)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&saved); err != nil {
			return err
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return errors.New("source inventory has trailing JSON or invalid content")
		}
		stamp, ok := saved.Creation["created"].(string)
		if !ok {
			return errors.New("source inventory timestamp missing")
		}
		if _, err := time.Parse(time.RFC3339, stamp); err != nil {
			return errors.New("source inventory timestamp invalid")
		}
		created = stamp
	}
	namespace := sha256.Sum256([]byte(hex.EncodeToString(verification[:]) + runtime.Version() + created))
	doc := document{
		Version: "SPDX-2.3", DataLicense: "CC0-1.0", ID: "SPDXRef-DOCUMENT",
		Name:      inventoryName,
		Namespace: "urn:sha256:" + hex.EncodeToString(namespace[:]),
		Creation:  map[string]any{"created": created, "creators": []string{"Tool: anachron-agent-gateway-source-sbom"}},
		Comment:   "Source-only inventory. Zero external Go modules; the Go toolchain/standard-library input is not a complete binary or platform inventory. No release binaries are distributed.",
		Files:     files,
		Packages: []map[string]any{
			{
				"SPDXID": "SPDXRef-Gateway", "name": module.Path, "versionInfo": sourceVersion,
				"downloadLocation": "NOASSERTION", "filesAnalyzed": true, "licenseDeclared": "Apache-2.0",
				"licenseConcluded": "NOASSERTION", "licenseInfoFromFiles": []string{"Apache-2.0", "BSD-3-Clause"},
				"copyrightText": "Copyright 2026 Julian Wiley",
				"packageVerificationCode": map[string]any{"packageVerificationCodeValue": hex.EncodeToString(verification[:]),
					"packageVerificationCodeExcludedFiles": []string{"./sbom.source.spdx.json"}},
			},
			{
				"SPDXID": "SPDXRef-Go", "name": "Go toolchain and standard-library build input", "versionInfo": runtime.Version(),
				"downloadLocation": "https://go.dev/dl/?mode=json", "filesAnalyzed": false,
				"licenseDeclared": "BSD-3-Clause", "licenseConcluded": "NOASSERTION", "copyrightText": "The Go Authors",
				"comment": "Root Go notice is reproduced in third_party/GO-LICENSE. Review binary/platform-specific composition separately before distribution.",
			},
		},
		Relationships: []map[string]string{
			{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Gateway"},
			{"spdxElementId": "SPDXRef-Go", "relationshipType": "BUILD_TOOL_OF", "relatedSpdxElement": "SPDXRef-Gateway"},
		},
	}
	for _, file := range files {
		doc.Relationships = append(doc.Relationships, map[string]string{
			"spdxElementId": "SPDXRef-Gateway", "relationshipType": "CONTAINS", "relatedSpdxElement": file.ID,
		})
	}
	if check != "" {
		// Compare decoded documents so map ordering and JSON number
		// representations do not bypass or spuriously fail metadata checks.
		expected, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		var normalized document
		if err := json.Unmarshal(expected, &normalized); err != nil {
			return err
		}
		if !reflect.DeepEqual(saved, normalized) {
			return errors.New("source inventory files or metadata differ; regenerate and review it")
		}
		fmt.Printf("source SBOM verified: %d files, exact module/toolchain metadata, no external module dependencies\n", len(files))
		return nil
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, append(data, '\n'), 0644); err != nil {
		return err
	}
	fmt.Printf("source SBOM generated: %d files, %s\n", len(files), runtime.Version())
	return nil
}
