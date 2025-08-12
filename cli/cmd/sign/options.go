// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"github.com/agntcy/dir/client"
	"github.com/agntcy/dir/utils/cosign"
)

var opts = &options{}

type options struct {
	// Signing options
	client.SignOpts
}

func init() {
	flags := Command.Flags()

	// Signing options
	flags.StringVar(&opts.FulcioURL, "fulcio-url", cosign.DefaultFulcioURL,
		"Sigstore Fulcio URL")
	flags.StringVar(&opts.RekorURL, "rekor-url", cosign.DefaultRekorURL,
		"Sigstore Rekor URL")
	flags.StringVar(&opts.TimestampURL, "timestamp-url", cosign.DefaultTimestampURL,
		"Sigstore Timestamp URL")
	flags.StringVar(&opts.OIDCProviderURL, "oidc-provider-url", cosign.DefaultOIDCProviderURL,
		"OIDC Provider URL")
	flags.StringVar(&opts.OIDCClientID, "oidc-client-id", cosign.DefaultOIDCClientID,
		"OIDC Client ID")
	flags.StringVar(&opts.OIDCToken, "oidc-token", "",
		"OIDC Token for non-interactive signing. ")
	flags.StringVar(&opts.Key, "key", "",
		"Path to the private key file to use for signing (e.g., a Cosign key generated with a GitHub token). Use this option to sign with a self-managed keypair instead of OIDC identity-based signing.")
	flags.StringVar(&opts.RegistryAddress, "registry-address", "",
		"Registry address for signature storage (defaults to client config)")
	flags.StringVar(&opts.RepositoryName, "repository-name", "",
		"Repository name for signature storage (defaults to client config)")
}
