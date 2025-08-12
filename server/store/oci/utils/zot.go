// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/agntcy/dir/utils/logging"
)

var logger = logging.Logger("store/oci/utils/zot")

// ZotConfig contains configuration for zot operations.
type ZotConfig struct {
	RegistryAddress string
	RepositoryName  string
	Username        string
	Password        string
	AccessToken     string
	Insecure        bool
	LocalDir        string
}

// UploadPublicKeyOptions contains options for uploading public keys to zot.
type UploadPublicKeyOptions struct {
	Config    *ZotConfig
	PublicKey string
}

// VerificationOptions contains options for zot verification.
type VerificationOptions struct {
	Config    *ZotConfig
	RecordCID string
}

// VerificationResult contains the result of zot verification.
type VerificationResult struct {
	IsSigned  bool
	IsTrusted bool
	Author    string
	Tool      string
}

// UploadPublicKeyToZot uploads a public key to zot for signature verification.
// This enables zot to mark signatures as "trusted" when they can be verified with this key.
func UploadPublicKeyToZot(ctx context.Context, opts *UploadPublicKeyOptions) error {
	logger.Debug("Uploading public key to zot for signature verification")

	if opts.PublicKey == "" {
		return errors.New("public key is required")
	}

	// Get registry URL for zot cosign endpoint
	registryURL := buildRegistryURL(opts.Config)
	uploadEndpoint := registryURL + "/v2/_zot/ext/cosign"

	// Create HTTP request with public key as body
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadEndpoint, strings.NewReader(opts.PublicKey))
	if err != nil {
		return fmt.Errorf("failed to create upload request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	// Add authentication
	addAuthentication(req, opts.Config)

	// Create HTTP client and execute request
	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload public key: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("failed to upload public key, status: %d, response: %s", resp.StatusCode, string(body))
	}

	logger.Debug("Successfully uploaded public key to zot", "endpoint", uploadEndpoint)

	return nil
}

// VerifyWithZot queries zot's verification API to check if a signature is valid.
//
//nolint:cyclop
func VerifyWithZot(ctx context.Context, opts *VerificationOptions) (*VerificationResult, error) {
	// Skip if using local storage
	if opts.Config.LocalDir != "" {
		logger.Debug("Skipping zot verification for local storage")

		return nil, errors.New("zot verification not available for local storage")
	}

	// Build zot search endpoint URL
	registryURL := buildRegistryURL(opts.Config)
	searchEndpoint := registryURL + "/v2/_zot/ext/search"
	logger.Debug("Querying zot for signature verification", "endpoint", searchEndpoint, "recordCID", opts.RecordCID)

	// Create GraphQL query for signature verification
	query := fmt.Sprintf(`{
		Image(image: "%s:%s") {
			Digest
			IsSigned
			Tag
			SignatureInfo {
				Tool
				IsTrusted
				Author
			}
		}
	}`, opts.Config.RepositoryName, opts.RecordCID)

	graphqlQuery := map[string]interface{}{
		"query": query,
	}

	jsonData, err := json.Marshal(graphqlQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GraphQL query: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, searchEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create verification request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add authentication
	addAuthentication(req, opts.Config)

	// Create HTTP client and execute request
	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query zot verification: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read verification response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		logger.Debug("Verification query returned non-success status", "status", resp.StatusCode, "body", string(body))

		return nil, fmt.Errorf("verification query returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse GraphQL response
	var graphqlResp struct {
		Data struct {
			Image struct {
				Digest        string `json:"Digest"`
				IsSigned      bool   `json:"IsSigned"`
				Tag           string `json:"Tag"`
				SignatureInfo []struct {
					Tool      string `json:"Tool"`
					IsTrusted bool   `json:"IsTrusted"`
					Author    string `json:"Author"`
				} `json:"SignatureInfo"`
			} `json:"Image"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &graphqlResp); err != nil {
		return nil, fmt.Errorf("failed to decode verification response: %w", err)
	}

	// Build result
	result := &VerificationResult{
		IsSigned:  graphqlResp.Data.Image.IsSigned,
		IsTrusted: false,
	}

	// Extract signature info if available
	if len(graphqlResp.Data.Image.SignatureInfo) > 0 {
		sigInfo := graphqlResp.Data.Image.SignatureInfo[0]
		result.IsTrusted = sigInfo.IsTrusted
		result.Author = sigInfo.Author
		result.Tool = sigInfo.Tool
	}

	logger.Debug("Zot verification result", "recordCID", opts.RecordCID, "isSigned", result.IsSigned, "isTrusted", result.IsTrusted)

	return result, nil
}

// buildRegistryURL constructs the registry URL with proper protocol.
func buildRegistryURL(config *ZotConfig) string {
	registryURL := config.RegistryAddress
	if !strings.HasPrefix(registryURL, "http://") && !strings.HasPrefix(registryURL, "https://") {
		if config.Insecure {
			registryURL = "http://" + registryURL
		} else {
			registryURL = "https://" + registryURL
		}
	}

	return registryURL
}

// addAuthentication adds authentication headers to HTTP requests.
func addAuthentication(req *http.Request, config *ZotConfig) {
	if config.Username != "" && config.Password != "" {
		req.SetBasicAuth(config.Username, config.Password)
	} else if config.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+config.AccessToken)
	}
}
