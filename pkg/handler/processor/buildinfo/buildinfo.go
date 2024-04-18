//
// Copyright 2022 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package buildinfo

import (
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/handler/processor"
)

type BuildInfoProcessor struct {
}

func (p *BuildInfoProcessor) ValidateSchema(d *processor.Document) error {
	if d.Type != processor.DocumentBuildInfo {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentBuildInfo, d.Type)
	}

	lines := strings.Split(string(d.Blob), "\n")

	expectedFields := map[string]bool{
		"Source":                  false,
		"Binary":                  false,
		"Version":                 false,
		"Installed-Build-Depends": false,
		"Checksums-Md5":           false,
		"Checksums-Sha1":          false,
		"Build-Origin":            false,
		"Build-Architecture":      false,
		"Build-Date":              false,
		"Build-Path":              false,
	}

	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)

		field := parts[0]

		if _, ok := expectedFields[field]; ok {
			expectedFields[field] = true
		}
	}

	for field, found := range expectedFields {
		if !found {
			return fmt.Errorf("field %s is missing\n in buildinfo", field)
		}
	}
	return nil
}

func (p *BuildInfoProcessor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentBuildInfo {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentBuildInfo, d.Type)
	}
	return []*processor.Document{}, nil
}
