// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	_ "embed"
	"os"
	"path/filepath"
	"time"

	"github.com/agntcy/dir/e2e/config"
	"github.com/agntcy/dir/e2e/utils"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

// Using the shared agent V3 data from embed.go

// Test constants.
const (
	tempDirPrefix = "sign-test"
)

// Test file paths helper.
type testPaths struct {
	tempDir         string
	record          string
	privateKey      string
	publicKey       string
	signature       string
	signatureOutput string
}

func setupTestPaths() *testPaths {
	tempDir, err := os.MkdirTemp("", tempDirPrefix)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	return &testPaths{
		tempDir:         tempDir,
		record:          filepath.Join(tempDir, "record.json"),
		signature:       filepath.Join(tempDir, "signature.json"),
		signatureOutput: filepath.Join(tempDir, "signature-output.json"),
		privateKey:      filepath.Join(tempDir, "cosign.key"),
		publicKey:       filepath.Join(tempDir, "cosign.pub"),
	}
}

var _ = ginkgo.Describe("Running dirctl end-to-end tests to check signature support", func() {
	var cli *utils.CLI

	ginkgo.BeforeEach(func() {
		if cfg.DeploymentMode != config.DeploymentModeLocal {
			ginkgo.Skip("Skipping test, not in local mode")
		}

		utils.ResetCLIState()
		// Initialize CLI helper
		cli = utils.NewCLI()
	})

	// Test params
	var (
		paths        *testPaths
		tempAgentCID string
	)

	ginkgo.Context("signature workflow", ginkgo.Ordered, func() {
		// Setup: Create temporary directory and files for the entire workflow
		ginkgo.BeforeAll(func() {
			var err error
			paths = setupTestPaths()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Write test agent to temp location
			err = os.WriteFile(paths.record, expectedAgentV3JSON, 0o600)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Generate cosign key pair for all tests
			utils.GenerateCosignKeyPair(paths.tempDir)

			// Verify key files were created
			gomega.Expect(paths.privateKey).To(gomega.BeAnExistingFile())
			gomega.Expect(paths.publicKey).To(gomega.BeAnExistingFile())

			// Set cosign password for all tests
			err = os.Setenv("COSIGN_PASSWORD", utils.TestPassword)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		// Cleanup: Remove temporary directory after all workflow tests
		ginkgo.AfterAll(func() {
			// Unset cosign password for all tests
			os.Unsetenv("COSIGN_PASSWORD")

			if paths != nil && paths.tempDir != "" {
				err := os.RemoveAll(paths.tempDir)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
			}
		})

		ginkgo.It("should create keys for signing", func() {
			// Keys are already created in BeforeAll, just verify they exist
			gomega.Expect(paths.privateKey).To(gomega.BeAnExistingFile())
			gomega.Expect(paths.publicKey).To(gomega.BeAnExistingFile())
		})

		ginkgo.It("should push a record to the store", func() {
			tempAgentCID = cli.Push(paths.record).ShouldSucceed()

			// Validate that the returned CID correctly represents the pushed data
			utils.LoadAndValidateCID(tempAgentCID, paths.record)
		})

		ginkgo.It("should sign a record with a key pair", func() {
			_ = cli.Sign(tempAgentCID, paths.privateKey).ShouldSucceed()

			time.Sleep(10 * time.Second)
		})

		ginkgo.It("should verify a signature with a public key on server side", func() {
			cli.Command("verify").
				WithArgs(tempAgentCID).
				ShouldContain("Record signature is trusted!")
		})
	})
})
