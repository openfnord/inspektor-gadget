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

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2/content/oci"
	oras_auth "oras.land/oras-go/v2/registry/remote/auth"
)

type AuthOptions struct {
	AuthFile string
}

var (
	validTagRegex   = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9_.-]*[a-zA-Z0-9]$")
	defaultOciStore = "/var/lib/ig/oci-store"
	DefaultAuthFile = "/var/lib/ig/config.json"
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

func GetHostString(repository string) (string, error) {
	// We need everything before the first slash, which includes also the port, but remove the scheme
	url, err := url.Parse(repository)
	if err != nil {
		return "", fmt.Errorf("parse url %q: %w", repository, err)
	}
	if url.Host != "" && url.Scheme != "" {
		return "", fmt.Errorf("no scheme allowed")
	}

	if len(repository) == 0 {
		return "", fmt.Errorf("empty repo url")
	}
	// mydomain.io could be a repository. So tolerate a string without "/"
	return strings.Split(repository, "/")[0], nil
}

func SetupAuthVariablesAndFlags(cmd *cobra.Command, authOptions *AuthOptions) {
	// Flag inspired by https://github.com/containers/common/blob/cac40138f7e3c2b29ca32e64348535516bf6aa51/pkg/auth/cli.go#L48
	cmd.Flags().StringVar(&authOptions.AuthFile, "authfile", DefaultAuthFile,
		"path of the authentication file. This overrides the REGISTRY_AUTH_FILE environment variable")
	viper.BindPFlag("registry.auth_file", cmd.Flags().Lookup("authfile"))
	viper.BindEnv("registry.auth_file", "REGISTRY_AUTH_FILE")
}

func CreateAuthClient(repository string, authOptions *AuthOptions) (*oras_auth.Client, error) {
	logrus.Debugf("Using auth file %q", authOptions.AuthFile)

	var cfg *configfile.ConfigFile
	var err error

	// 1. Explicitly setting the auth file
	// 2. Using the default auth file
	// 3. Using the default docker auth file if 2. doesn't exist
	if authOptions.AuthFile != DefaultAuthFile {
		authFileReader, err := os.Open(authOptions.AuthFile)
		if err != nil {
			return nil, fmt.Errorf("open auth file %q: %w", authOptions.AuthFile, err)
		}
		defer authFileReader.Close()
		cfg, err = config.LoadFromReader(authFileReader)
		if err != nil {
			return nil, fmt.Errorf("load auth config: %w", err)
		}
	} else if _, err := os.Stat(authOptions.AuthFile); err == nil {
		authFileReader, err := os.Open(authOptions.AuthFile)
		if err != nil {
			return nil, fmt.Errorf("open auth file %q: %w", authOptions.AuthFile, err)
		}
		defer authFileReader.Close()
		cfg, err = config.LoadFromReader(authFileReader)
		if err != nil {
			return nil, fmt.Errorf("load auth config: %w", err)
		}
	} else {
		logrus.Debugf("Couldn't find default auth file %q...", authOptions.AuthFile)
		logrus.Debugf("Using default docker auth file instead")
		logrus.Debugf("$HOME: %q", os.Getenv("HOME"))

		cfg, err = config.Load("")
		if err != nil {
			return nil, fmt.Errorf("load auth config: %w", err)
		}
	}

	hostString, err := GetHostString(repository)
	if err != nil {
		return nil, fmt.Errorf("get host string: %w", err)
	}
	authConfig, err := cfg.GetAuthConfig(hostString)
	if err != nil {
		return nil, fmt.Errorf("get auth config: %w", err)
	}

	return &oras_auth.Client{
		Credential: oras_auth.StaticCredential(hostString, oras_auth.Credential{
			Username:    authConfig.Username,
			Password:    authConfig.Password,
			AccessToken: authConfig.Auth,
		}),
	}, nil
}
