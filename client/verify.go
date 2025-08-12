// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	signv1 "github.com/agntcy/dir/api/sign/v1"
	"github.com/agntcy/dir/utils/cosign"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// VerifyWithOIDC verifies the signature of the record using OIDC.
func (c *Client) VerifyWithOIDC(_ context.Context, req *signv1.VerifyRequest) (*signv1.VerifyResponse, error) {
	// Validate request.
	if req.GetRecord() == nil {
		return nil, errors.New("record must be set")
	}

	if req.GetSignature() == nil {
		return nil, errors.New("signature must be set")
	}

	// Extract signature data.
	sigBundleRawJSON, err := base64.StdEncoding.DecodeString(req.GetSignature().GetContentBundle())
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	sigBundle := &bundle.Bundle{}
	if err := sigBundle.UnmarshalJSON(sigBundleRawJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signature bundle: %w", err)
	}

	// Convert the record to JSON.
	recordJSON, err := json.Marshal(req.GetRecord())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal record: %w", err)
	}

	oidcVerifier := req.GetProvider().GetOidc()

	// Load identity verification options.
	var identityPolicy verify.PolicyOption
	{
		// Create OIDC identity matcher for verification.
		certID, err := verify.NewShortCertificateIdentity("", oidcVerifier.GetExpectedIssuer(), "", oidcVerifier.GetExpectedSigner())
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate identity: %w", err)
		}

		identityPolicy = verify.WithCertificateIdentity(certID)
	}

	// Load trusted root material.
	var trustedMaterial root.TrustedMaterialCollection
	{
		// Get staging TUF trusted root.
		// TODO: allow switching between TUF environments.
		fetcher := fetcher.NewDefaultFetcher()
		fetcher.SetHTTPUserAgent(util.ConstructUserAgent())
		tufOptions := &tuf.Options{
			Root:              tuf.StagingRoot(),
			RepositoryBaseURL: tuf.StagingMirror,
			Fetcher:           fetcher,
			DisableLocalCache: true, // read-only mode; prevent from pulling root CA to local dir
		}

		tufClient, err := tuf.New(tufOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create TUF client: %w", err)
		}

		trustedRoot, err := root.GetTrustedRoot(tufClient)
		if err != nil {
			return nil, fmt.Errorf("failed to get trusted root: %w", err)
		}

		trustedMaterial = append(trustedMaterial, trustedRoot)
	}

	// Create verifier session.
	sev, err := verify.NewVerifier(trustedMaterial,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithObserverTimestamps(1),
		verify.WithTransparencyLog(1),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	// Run verification
	_, err = sev.Verify(sigBundle, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(recordJSON)), identityPolicy))
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature: %w", err)
	}

	response := &signv1.VerifyResponse{
		Success: err == nil,
	}

	// Verify the signature.
	return response, nil
}

// VerifyWithKey verifies the signature of the record using a PEM-encoded public key.
func (c *Client) VerifyWithKey(_ context.Context, req *signv1.VerifyRequest) (*signv1.VerifyResponse, error) {
	keyVerifier := req.GetProvider().GetKey()

	// Validate request.
	if req.GetRecord() == nil {
		return nil, errors.New("record must be set")
	}

	if req.GetSignature() == nil {
		return nil, errors.New("signature must be set")
	}

	// Extract signature data.
	sigBundleRawJSON, err := base64.StdEncoding.DecodeString(req.GetSignature().GetContentBundle())
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	sigBundle := &bundle.Bundle{}
	if err := sigBundle.UnmarshalJSON(sigBundleRawJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signature bundle: %w", err)
	}

	// Get the public key from the signature bundle and compare it with the provided key.
	sigBundleVerificationMaterial := sigBundle.VerificationMaterial
	if sigBundleVerificationMaterial == nil {
		return nil, errors.New("signature bundle has no verification material")
	}

	pubKey := sigBundleVerificationMaterial.GetPublicKey()
	if pubKey == nil {
		return nil, errors.New("signature bundle verification material has no public key")
	}

	// Decode the PEM-encoded public key and generate the expected hint.
	p, _ := pem.Decode(keyVerifier.GetPublicKey())
	if p == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	if p.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s", p.Type)
	}

	expectedHint := string(cosign.GenerateHintFromPublicKey(p.Bytes))

	if pubKey.GetHint() != expectedHint {
		return nil, fmt.Errorf("public key hint mismatch: expected %s, got %s", expectedHint, pubKey.GetHint())
	}

	response := &signv1.VerifyResponse{
		Success: err == nil,
	}

	return response, nil
}

// VerifyWithZot verifies the signature of the record using zot's verification API via the server.
func (c *Client) VerifyWithZot(ctx context.Context, req *signv1.VerifyRequest) (*signv1.VerifyResponse, error) {
	// Validate request.
	if req.GetRecord() == nil || req.GetRecord().GetCid() == "" {
		return nil, errors.New("record must be set and have a CID")
	}

	// Call the server's SignService.Verify method
	response, err := c.SignServiceClient.Verify(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("server verification failed: %w", err)
	}

	return response, nil
}
