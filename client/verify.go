// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"

	signv1 "github.com/agntcy/dir/api/sign/v1"
)

// VerifyWithZot verifies the signature of the record using zot's verification API via the server.
func (c *Client) VerifyWithZot(ctx context.Context, req *signv1.VerifyRequest) (*signv1.VerifyResponse, error) {
	// Call the server's SignService.Verify method
	response, err := c.SignServiceClient.Verify(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("server verification failed: %w", err)
	}

	return response, nil
}
