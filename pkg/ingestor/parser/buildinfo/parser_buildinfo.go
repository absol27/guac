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

// Matching hash to relevant binary is not trivial, could use packagelist dump to match binary to deb file
// Using all as direct dependencies not sure if that is correct
// Add info about source but that needs VCS url, Should I add data like VCS url to source?
// All binaries are top level packages, with same dependencies

package buildinfo

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	asmhelpers "github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

type BuildInfo struct {
	InstalledBuildDepends []string  `json:"installedBuildDepends"`
	Source                string    `json:"source"`
	Binary                []string  `json:"binary"`
	Version               string    `json:"version"`
	Architecture          string    `json:"architecture"`
	Distro                string    `json:"distro"`
	BuildDate             time.Time `json:"builddate"`
}

type buildinfoParser struct {
	doc               *processor.Document
	source            *model.SourceInputSpec
	binaries          map[string][]*model.PkgInputSpec
	dependencies      map[string][]*model.PkgInputSpec
	packageArtifacts  map[string][]*model.ArtifactInputSpec
	identifierStrings *common.IdentifierStrings
	buildinfo         BuildInfo
}

func NewBuildInfoParser() common.DocumentParser {
	return &buildinfoParser{
		binaries:          map[string][]*model.PkgInputSpec{},
		source:            &model.SourceInputSpec{},
		dependencies:      map[string][]*model.PkgInputSpec{},
		packageArtifacts:  map[string][]*model.ArtifactInputSpec{},
		identifierStrings: &common.IdentifierStrings{},
	}
}

// Parse breaks out the document into the graph components
func (b *buildinfoParser) Parse(ctx context.Context, doc *processor.Document) error {
	b.doc = doc
	buildinfo, err := parsebuildInfoBlob(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse buildinfo document: %w", err)
	}
	b.buildinfo = buildinfo
	if err := b.getTopLevelPackage(); err != nil {
		return err
	}
	if err := b.getDependencies(); err != nil {
		return err
	}
	return nil
}

// GetIdentities gets the identity node from the document if they exist
func (c *buildinfoParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (b *buildinfoParser) getTopLevelPackage() error {
	// Get the source package
	if b.buildinfo.Source != "" {
		b.source = &model.SourceInputSpec{
			// Do I need to add the VCS url here?
			Type:      "deb",
			Namespace: b.buildinfo.Distro + "-src",
			Name:      b.buildinfo.Source,
		}
	}
	for _, binary := range b.buildinfo.Binary {
		if binary != "" {
			purl := guacBuildInfoPkgPurl(binary, b.buildinfo.Version, b.buildinfo.Architecture, b.buildinfo.Distro)

			pkg, err := asmhelpers.PurlToPkg(purl)
			if err != nil {
				return err
			}
			b.identifierStrings.PurlStrings = append(b.identifierStrings.PurlStrings, purl)

			b.binaries[purl] = append(b.binaries[purl], pkg)

		} else {
			return fmt.Errorf("no binary found in buildinfo document")
		}
	}
	return nil
}

func (b *buildinfoParser) getDependencies() error {
	for _, dep := range b.buildinfo.InstalledBuildDepends {
		depParts := strings.SplitN(dep, "(=", 2)
		if len(depParts) != 2 {
			return fmt.Errorf("failed to parse dependency %s", dep)
		}
		depName := depParts[0]
		depVersion := strings.TrimRight(depParts[1], "),")
		purl := guacBuildInfoPkgPurl(depName, depVersion, b.buildinfo.Architecture, b.buildinfo.Distro)
		depPackage, err := asmhelpers.PurlToPkg(purl)
		if err != nil {
			return err
		}
		b.dependencies["InstalledBuildDepends"] = append(b.dependencies["InstalledBuildDepends"], depPackage)
	}
	return nil
}

func parsebuildInfoBlob(p []byte) (BuildInfo, error) {
	lines := strings.Split(string(p), "\n")

	var buildInfo BuildInfo

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 && strings.Contains(parts[0], "(=") {
			buildInfo.InstalledBuildDepends = append(buildInfo.InstalledBuildDepends, strings.ReplaceAll(parts[0], " ", ""))
		}
		if len(parts) == 2 {
			field := parts[0]
			value := parts[1]
			switch field {
			case "Source":
				buildInfo.Source = value
			case "Binary":
				buildInfo.Binary = strings.Fields(value)
			case "Version":
				buildInfo.Version = value
			case "Build-Architecture":
				buildInfo.Architecture = value
			case "Build-Origin":
				buildInfo.Distro = strings.ToLower(value)
			case "Build-Date":
				t, err := time.Parse(time.RFC1123Z, value)
				if err != nil {
					fmt.Println("Error parsing date:", err)
				}
				buildInfo.BuildDate = t
			}
		}
	}
	return buildInfo, nil
}

func (c *buildinfoParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return c.identifierStrings, nil
}

func (b *buildinfoParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	preds := &assembler.IngestPredicates{}

	for _, purl := range b.identifierStrings.PurlStrings {
		for _, binary := range b.binaries[purl] {
			x := []assembler.HasSourceAtIngest{}
			a := assembler.HasSourceAtIngest{
				Pkg: binary,
				Src: b.source,
				HasSourceAt: &model.HasSourceAtInputSpec{
					KnownSince:    b.buildinfo.BuildDate,
					Justification: "Binaries are built from source package",
					Origin:        "Debian BuildInfo Source",
					Collector:     "Buildinfo file",
				},
				PkgMatchFlag: common.GetMatchFlagsFromPkgInput(binary),
			}
			x = append(x, a)
			fmt.Println(a)
			fmt.Println(x)
			preds.HasSourceAt = append(preds.HasSourceAt, x...)
			preds.IsDependency = append(preds.IsDependency, common.CreateTopLevelIsDeps(binary, b.dependencies, nil, "Debian BuildInfo Dependency")...)
		}
	}

	return preds
}

// https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst
// pkg:deb/debian/attr@1:2.4.47-2%2Bb1?arch=amd64
func guacBuildInfoPkgPurl(componentName string, version string, arch string, distro string) string {
	purl := ""
	typeNamespaceString := ""
	escapedName := asmhelpers.SanitizeString(componentName)
	// if topLevel {
	typeNamespaceString = "pkg:deb/" + distro + "/"
	// } else {
	// 	// Is this needed in the purl?
	// 	typeNamespaceString = asmhelpers.PurlPkgGuac
	// }
	if version != "" && arch != "" {
		purl = typeNamespaceString + escapedName + "@" + version + "?arch=" + arch
	} else if version != "" {
		purl = typeNamespaceString + escapedName + "@" + version
	}
	return purl
}
