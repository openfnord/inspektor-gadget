// Copyright 2023 The Inspektor Gadget authors
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

package utils

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"oras.land/oras-go/v2/content/oci"
)

var (
	validTagRegex   = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9_.-]*[a-zA-Z0-9]$")
	defaultOciStore = "/var/lib/ig/oci-store"
)

func GetLocalOciStore() (*oci.Store, error) {
	if err := os.MkdirAll(filepath.Dir(defaultOciStore), 0o710); err != nil {
		return nil, err
	}
	return oci.New(defaultOciStore)
}

func isValidTag(tag string) bool {
	// Check if the tag is not empty
	if tag == "" {
		return false
	}
	// Check if the tag's length is within the allowed limit
	if len(tag) > 128 {
		return false
	}
	// Check if the input string matches the pattern
	return validTagRegex.MatchString(tag)
}

func GetTagFromImage(image string) (string, error) {
	url, err := url.Parse(image)
	if err != nil {
		return "", fmt.Errorf("parse url %q: %w", image, err)
	}
	if url.Host != "" && url.Scheme != "" {
		return "", fmt.Errorf("no scheme allowed")
	}

	if len(image) == 0 {
		return "", fmt.Errorf("empty image")
	}
	index := strings.LastIndexByte(image, ':')
	// image without a tag
	if index == -1 {
		return "latest", nil
	}
	tag := image[index+1:]
	if !isValidTag(tag) {
		return "", fmt.Errorf("%q is not a valid tag", tag)
	}
	return tag, nil
}

func GetRepositoryFromImage(image string) (string, error) {
	// For now just assume its something like ghcr.io:443/inspektor-gadget/ig:latest
	// So we need everything before the last colon, which includes also the port
	url, err := url.Parse(image)
	if err != nil {
		return "", fmt.Errorf("parse url %q: %w", image, err)
	}
	if url.Host != "" && url.Scheme != "" {
		return "", fmt.Errorf("no scheme allowed")
	}

	if len(image) == 0 {
		return "", fmt.Errorf("empty image")
	}
	index := strings.LastIndexByte(image, ':')
	// image without a tag
	if index == -1 {
		return image, nil
	}
	tag := image[index+1:]
	if !isValidTag(tag) {
		return "", fmt.Errorf("%q is not a valid tag", tag)
	}
	return image[:index], nil
}

func NormalizeImage(image string) (string, error) {
	tag, err := GetTagFromImage(image)
	if err != nil {
		return "", fmt.Errorf("get tag from image %q: %w", image, err)
	}
	repository, err := GetRepositoryFromImage(image)
	if err != nil {
		return "", fmt.Errorf("get repository from image %q: %w", image, err)
	}
	return fmt.Sprintf("%s:%s", repository, tag), nil
}
