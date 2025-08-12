// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	storev1 "github.com/agntcy/dir/api/store/v1"
	ociconfig "github.com/agntcy/dir/server/store/oci/config"
	zotconfig "github.com/agntcy/dir/server/sync/config/zot"
	synctypes "github.com/agntcy/dir/server/sync/types"
	"github.com/agntcy/dir/server/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Worker processes sync work items.
type Worker struct {
	id        int
	db        types.SyncDatabaseAPI
	store     types.StoreAPI
	workQueue <-chan synctypes.WorkItem
	timeout   time.Duration
}

// NewWorker creates a new worker instance.
func NewWorker(id int, db types.SyncDatabaseAPI, store types.StoreAPI, workQueue <-chan synctypes.WorkItem, timeout time.Duration) *Worker {
	return &Worker{
		id:        id,
		db:        db,
		store:     store,
		workQueue: workQueue,
		timeout:   timeout,
	}
}

// Run starts the worker loop.
func (w *Worker) Run(ctx context.Context, stopCh <-chan struct{}) {
	logger.Info("Starting sync worker", "worker_id", w.id)

	for {
		select {
		case <-ctx.Done():
			logger.Info("Worker stopping due to context cancellation", "worker_id", w.id)

			return
		case <-stopCh:
			logger.Info("Worker stopping due to stop signal", "worker_id", w.id)

			return
		case workItem := <-w.workQueue:
			w.processWorkItem(ctx, workItem)
		}
	}
}

// processWorkItem handles a single sync work item.
func (w *Worker) processWorkItem(ctx context.Context, item synctypes.WorkItem) {
	logger.Info("Processing sync work item", "worker_id", w.id, "sync_id", item.SyncID, "remote_url", item.RemoteDirectoryURL)
	// TODO Check if store is oci and zot. If not, fail

	// Create timeout context for this work item
	workCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	var finalStatus storev1.SyncStatus

	switch item.Type {
	case synctypes.WorkItemTypeSyncCreate:
		finalStatus = storev1.SyncStatus_SYNC_STATUS_IN_PROGRESS

		err := w.addSync(workCtx, item)
		if err != nil {
			logger.Error("Sync failed", "worker_id", w.id, "sync_id", item.SyncID, "error", err)

			finalStatus = storev1.SyncStatus_SYNC_STATUS_FAILED
		}

	case synctypes.WorkItemTypeSyncDelete:
		finalStatus = storev1.SyncStatus_SYNC_STATUS_DELETED

		err := w.deleteSync(workCtx, item)
		if err != nil {
			logger.Error("Sync delete failed", "worker_id", w.id, "sync_id", item.SyncID, "error", err)

			finalStatus = storev1.SyncStatus_SYNC_STATUS_FAILED
		}

	default:
		logger.Error("Unknown work item type", "worker_id", w.id, "sync_id", item.SyncID, "type", item.Type)
	}

	// Update status in database
	if err := w.db.UpdateSyncStatus(item.SyncID, finalStatus); err != nil {
		logger.Error("Failed to update sync status", "worker_id", w.id, "sync_id", item.SyncID, "status", finalStatus, "error", err)
	}
}

func (w *Worker) deleteSync(workCtx context.Context, item synctypes.WorkItem) error {
	logger.Debug("Starting sync delete operation", "worker_id", w.id, "sync_id", item.SyncID, "remote_url", item.RemoteDirectoryURL)

	// Get remote registry URL from sync object
	remoteRegistryURL, err := w.db.GetSyncRemoteRegistry(item.SyncID)
	if err != nil {
		return fmt.Errorf("failed to get remote registry URL: %w", err)
	}

	// Remove registry from zot configuration
	if err := w.removeRegistryFromZotSync(workCtx, remoteRegistryURL); err != nil {
		return fmt.Errorf("failed to remove registry from zot sync: %w", err)
	}

	return nil
}

// addSync implements the core synchronization logic.
//
//nolint:unparam
func (w *Worker) addSync(ctx context.Context, item synctypes.WorkItem) error {
	logger.Debug("Starting sync operation", "worker_id", w.id, "sync_id", item.SyncID, "remote_url", item.RemoteDirectoryURL)

	// Negotiate credentials with remote node using RequestRegistryCredentials RPC
	remoteRegistryURL, err := w.negotiateCredentials(ctx, item.RemoteDirectoryURL)
	if err != nil {
		return fmt.Errorf("failed to negotiate credentials: %w", err)
	}

	// Store credentials for later use in sync process
	logger.Debug("Credentials negotiated successfully", "worker_id", w.id, "sync_id", item.SyncID)

	// Update sync object with remote registry URL
	if err := w.db.UpdateSyncRemoteRegistry(item.SyncID, remoteRegistryURL); err != nil {
		return fmt.Errorf("failed to update sync remote registry: %w", err)
	}

	// Update zot configuration with sync extension to trigger sync
	if err := w.addRegistryToZotSync(ctx, remoteRegistryURL); err != nil {
		return fmt.Errorf("failed to add registry to zot sync: %w", err)
	}

	logger.Debug("Sync operation completed", "worker_id", w.id, "sync_id", item.SyncID)

	return nil
}

// negotiateCredentials negotiates registry credentials with the remote Directory node.
func (w *Worker) negotiateCredentials(ctx context.Context, remoteDirectoryURL string) (string, error) {
	logger.Debug("Starting credential negotiation", "worker_id", w.id, "remote_url", remoteDirectoryURL)

	// Create gRPC connection to the remote Directory node
	conn, err := grpc.NewClient(
		remoteDirectoryURL,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create gRPC connection to remote node %s: %w", remoteDirectoryURL, err)
	}
	defer conn.Close()

	// Create SyncService client
	syncClient := storev1.NewSyncServiceClient(conn)

	// TODO: Get actual peer ID from the routing system or configuration
	requestingNodeID := "directory://local-node"

	// Make the credential negotiation request
	resp, err := syncClient.RequestRegistryCredentials(ctx, &storev1.RequestRegistryCredentialsRequest{
		RequestingNodeId: requestingNodeID,
	})
	if err != nil {
		return "", fmt.Errorf("failed to request registry credentials from %s: %w", remoteDirectoryURL, err)
	}

	// Check if the negotiation was successful
	if !resp.GetSuccess() {
		return "", fmt.Errorf("credential negotiation failed: %s", resp.GetErrorMessage())
	}

	logger.Info("Successfully negotiated registry credentials", "worker_id", w.id, "remote_url", remoteDirectoryURL, "registry_url", resp.GetRemoteRegistryUrl())

	// TODO: Get credentials from the response
	return resp.GetRemoteRegistryUrl(), nil
}

// readZotConfig reads and parses the zot configuration file.
func (w *Worker) readZotConfig() (*zotconfig.Config, error) {
	config, err := os.ReadFile(zotconfig.DefaultZotConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read zot config file %s: %w", zotconfig.DefaultZotConfigPath, err)
	}

	logger.Debug("Read zot config file", "worker_id", w.id, "file", string(config))

	var zotConfig zotconfig.Config
	if err := json.Unmarshal(config, &zotConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal zot config: %w", err)
	}

	return &zotConfig, nil
}

// writeZotConfig marshals and writes the zot configuration file.
func (w *Worker) writeZotConfig(zotConfig *zotconfig.Config) error {
	updatedConfig, err := json.MarshalIndent(zotConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated zot config: %w", err)
	}

	if err := os.WriteFile(zotconfig.DefaultZotConfigPath, updatedConfig, 0o644); err != nil { //nolint:gosec,mnd
		return fmt.Errorf("failed to write updated zot config: %w", err)
	}

	return nil
}

// addRegistryToZotSync adds a registry to the zot sync configuration.
func (w *Worker) addRegistryToZotSync(_ context.Context, remoteDirectoryURL string) error {
	logger.Debug("Adding registry to zot sync", "worker_id", w.id, "remote_url", remoteDirectoryURL)

	// Validate input
	if remoteDirectoryURL == "" {
		return errors.New("remote directory URL cannot be empty")
	}

	// Read current zot config
	zotConfig, err := w.readZotConfig()
	if err != nil {
		return err
	}

	// Initialize extensions if nil
	if zotConfig.Extensions == nil {
		zotConfig.Extensions = &zotconfig.Extensions{}
	}

	// Initialize sync config if nil
	syncConfig := zotConfig.Extensions.Sync
	if syncConfig == nil {
		syncConfig = &zotconfig.SyncConfig{}
		zotConfig.Extensions.Sync = syncConfig
	}

	syncConfig.Enable = toPtr(true)

	// Create registry configuration with credentials if provided
	// Add http:// scheme if not present for zot sync
	registryURL, err := w.normalizeRegistryURL(remoteDirectoryURL)
	if err != nil {
		return fmt.Errorf("failed to normalize registry URL: %w", err)
	}

	// Check if registry already exists
	for _, existingRegistry := range syncConfig.Registries {
		for _, existingURL := range existingRegistry.URLs {
			if existingURL == registryURL {
				logger.Debug("Registry already exists in zot config", "worker_id", w.id, "registry_url", registryURL)

				return nil
			}
		}
	}

	registry := zotconfig.SyncRegistryConfig{
		URLs:         []string{registryURL},
		OnDemand:     false, // Disable OnDemand for proactive sync
		PollInterval: zotconfig.DefaultPollInterval,
		MaxRetries:   zotconfig.DefaultMaxRetries,
		RetryDelay:   zotconfig.DefaultRetryDelay,
		TLSVerify:    toPtr(false),
		Content: []zotconfig.SyncContent{
			{
				Prefix: ociconfig.DefaultRepositoryName,
			},
		},
	}
	syncConfig.Registries = append(syncConfig.Registries, registry)

	logger.Debug("Registry added to zot sync", "worker_id", w.id, "remote_url", remoteDirectoryURL, "registry_url", registryURL)

	// Write the updated config back to the file
	if err := w.writeZotConfig(zotConfig); err != nil {
		return err
	}

	logger.Info("Successfully added registry to zot sync", "worker_id", w.id, "remote_url", remoteDirectoryURL)

	return nil
}

// removeRegistryFromZotSync removes a registry from the zot sync configuration.
func (w *Worker) removeRegistryFromZotSync(_ context.Context, remoteRegistryURL string) error {
	logger.Debug("Removing registry from zot sync", "worker_id", w.id, "remote_registry_url", remoteRegistryURL)

	// Validate input
	if remoteRegistryURL == "" {
		return errors.New("remote directory URL cannot be empty")
	}

	// Read current zot config
	zotConfig, err := w.readZotConfig()
	if err != nil {
		return err
	}

	// Check if sync config exists
	if zotConfig.Extensions == nil || zotConfig.Extensions.Sync == nil {
		logger.Debug("No sync configuration found", "worker_id", w.id)

		return nil
	}

	syncConfig := zotConfig.Extensions.Sync

	// Normalize the URL to match what would be stored
	registryURL, err := w.normalizeRegistryURL(remoteRegistryURL)
	if err != nil {
		return fmt.Errorf("failed to normalize registry URL: %w", err)
	}

	// Find and remove the registry
	var filteredRegistries []zotconfig.SyncRegistryConfig

	for _, registry := range syncConfig.Registries {
		found := false

		for _, url := range registry.URLs {
			if url == registryURL {
				found = true

				break
			}
		}

		if !found {
			filteredRegistries = append(filteredRegistries, registry)
		}
	}

	if len(filteredRegistries) == len(syncConfig.Registries) {
		logger.Debug("Registry not found in zot config", "worker_id", w.id, "registry_url", registryURL)

		return nil
	}

	syncConfig.Registries = filteredRegistries

	// Write the updated config back to the file
	if err := w.writeZotConfig(zotConfig); err != nil {
		return err
	}

	logger.Info("Successfully removed registry from zot sync", "worker_id", w.id)

	return nil
}

// normalizeRegistryURL ensures the registry URL has the proper scheme for zot sync.
func (w *Worker) normalizeRegistryURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", errors.New("registry URL cannot be empty")
	}

	// Add http:// scheme if not present for zot sync
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "http://" + rawURL, nil
	}

	// Validate the URL format
	if _, err := url.Parse(rawURL); err != nil {
		return "", fmt.Errorf("invalid URL format: %w", err)
	}

	return rawURL, nil
}

func toPtr[T any](v T) *T {
	return &v
}
