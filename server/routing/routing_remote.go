// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"context"
	"fmt"
	"strings"
	"time"

	routingtypes "github.com/agntcy/dir/api/routing/v1alpha2"
	"github.com/agntcy/dir/server/routing/internal/p2p"
	"github.com/agntcy/dir/server/routing/rpc"
	"github.com/agntcy/dir/server/types"
	"github.com/agntcy/dir/server/types/adapters"
	"github.com/agntcy/dir/utils/logging"
	"github.com/ipfs/go-cid"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p-kad-dht/providers"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ProtocolPrefix     = "dir"
	ProtocolRendezvous = "dir/connect"

	// refresh interval for DHT routing tables.
	refreshInterval = 30 * time.Second

	remoteLogger = logging.Logger("routing/remote")
)

// this interface handles routing across the network.
// TODO: we shoud add caching here.
type routeRemote struct {
	storeAPI types.StoreAPI
	server   *p2p.Server
	service  *rpc.Service
	notifyCh chan *handlerSync
}

//nolint:mnd
func newRemote(ctx context.Context,
	parentRouter types.RoutingAPI,
	storeAPI types.StoreAPI,
	dstore types.Datastore,
	opts types.APIOptions,
) (*routeRemote, error) {
	// Create routing
	routeAPI := &routeRemote{
		storeAPI: storeAPI,
		notifyCh: make(chan *handlerSync, 1000),
	}

	// Create P2P server
	server, err := p2p.New(ctx,
		p2p.WithListenAddress(opts.Config().Routing.ListenAddress),
		p2p.WithBootstrapAddrs(opts.Config().Routing.BootstrapPeers),
		p2p.WithRefreshInterval(refreshInterval),
		p2p.WithRandevous(ProtocolRendezvous), // enable libp2p auto-discovery
		p2p.WithIdentityKeyPath(opts.Config().Routing.KeyPath),
		p2p.WithCustomDHTOpts(
			func(h host.Host) ([]dht.Option, error) {
				// create provider manager
				providerMgr, err := providers.NewProviderManager(h.ID(), h.Peerstore(), dstore)
				if err != nil {
					return nil, fmt.Errorf("failed to create provider manager: %w", err)
				}

				// return custom opts for DHT
				return []dht.Option{
					dht.Datastore(dstore),                           // custom DHT datastore
					dht.ProtocolPrefix(protocol.ID(ProtocolPrefix)), // custom DHT protocol prefix
					dht.ProviderStore(&handler{
						ProviderManager: providerMgr,
						hostID:          h.ID().String(),
						notifyCh:        routeAPI.notifyCh,
					}),
				}, nil
			},
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create p2p: %w", err)
	}

	// update server pointers
	routeAPI.server = server

	// Register RPC server
	rpcService, err := rpc.New(server.Host(), storeAPI, parentRouter)
	if err != nil {
		defer server.Close()

		return nil, fmt.Errorf("failed to create RPC service: %w", err)
	}

	// update service
	routeAPI.service = rpcService

	// run listener in background
	go routeAPI.handleNotify(ctx)

	return routeAPI, nil
}

func (r *routeRemote) Publish(ctx context.Context, record types.Record) error {
	remoteLogger.Debug("Called remote routing's Publish method", "record", record)

	cidString := record.GetCid()
	if cidString == "" {
		return status.Errorf(codes.InvalidArgument, "invalid record: missing CID")
	}

	recordData := record.GetRecordData()
	if recordData == nil {
		return status.Errorf(codes.InvalidArgument, "invalid record: missing data")
	}

	// Parse CID string to cid.Cid for DHT operations
	digestCID, err := cid.Parse(cidString)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid CID format: %v", err)
	}

	// Announce to the DHT network that we are providing this content
	if r.server != nil && r.server.DHT() != nil {
		err = r.server.DHT().Provide(ctx, digestCID, true)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to announce to DHT: %v", err)
		}

		remoteLogger.Info("Successfully announced record to DHT", "cid", cidString)
	} else {
		return status.Errorf(codes.Internal, "DHT server not available")
	}

	return nil
}

func (r *routeRemote) List(ctx context.Context, req *routingtypes.ListRequest) (<-chan *routingtypes.ListResponse, error) {
	remoteLogger.Debug("Called remote routing's List method", "req", req)

	// For remote routing, List should search the DHT network for providers
	outCh := make(chan *routingtypes.ListResponse)

	// TODO: This needs a more sophisticated implementation to search DHT
	// For now, we'll return an empty channel since the main List functionality
	// is handled by local routing in v1alpha2 API
	go func() {
		defer close(outCh)

		// In v1alpha2, List is typically local-only
		// Network search functionality would be in a separate Search method
		remoteLogger.Debug("Remote List not fully implemented - v1alpha2 uses local List + separate Search")
	}()

	return outCh, nil
}

func (r *routeRemote) Unpublish(ctx context.Context, record types.Record) error {
	remoteLogger.Debug("Called remote routing's Unpublish method", "record", record)

	cidString := record.GetCid()
	if cidString == "" {
		return status.Errorf(codes.InvalidArgument, "invalid record: missing CID")
	}

	recordData := record.GetRecordData()
	if recordData == nil {
		return status.Errorf(codes.InvalidArgument, "invalid record: missing data")
	}

	// Validate CID format (even though we don't need to use it for unproviding)
	_, err := cid.Parse(cidString)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid CID format: %v", err)
	}

	// In libp2p DHT, there's no direct "unprovide" method
	// Provider records naturally expire, but we can stop announcing
	if r.server != nil && r.server.DHT() != nil {
		// We can't explicitly unprovide in libp2p DHT, but we can:
		// 1. Stop announcing this CID (by not calling Provide again)
		// 2. The record will naturally expire from the DHT

		remoteLogger.Info("Stopped providing record to DHT (will expire naturally)", "cid", cidString)

		// Note: In production, you might want to track what we're providing
		// and implement a cleanup mechanism, but for now this is sufficient
	} else {
		return status.Errorf(codes.Internal, "DHT server not available")
	}

	return nil
}

func (r *routeRemote) handleNotify(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// check if anything on notify
procLoop:
	for {
		select {
		case <-ctx.Done():
			return
		case notif := <-r.notifyCh:

			// check if we have this agent locally
			_, err := r.storeAPI.Lookup(ctx, notif.Ref)
			if err != nil {
				remoteLogger.Error("failed to check if agent exists locally", "error", err)

				continue procLoop
			}

			// TODO: we should subscribe to some agents so we can create a local copy
			// of the agent and its skills.
			// for now, we are only testing if we can reach out and fetch it from the
			// broadcasting node

			// lookup from remote
			meta, err := r.service.Lookup(ctx, notif.Peer.ID, notif.Ref)
			if err != nil {
				remoteLogger.Error("failed to lookup agent", "error", err)

				continue procLoop
			}

			// fetch model directly from peer and drop it
			record, err := r.service.Pull(ctx, notif.Peer.ID, notif.Ref)
			if err != nil {
				remoteLogger.Error("failed to pull record", "error", err)

				continue procLoop
			}

			// Create record adapter to work with the types.Record interface
			recordAdapter := adapters.NewRecordAdapter(record)

			// extract labels using the adapter system
			labels := getLabels(recordAdapter)

			// TODO: we can perform validation and data synchronization here.
			// Depending on the server configuration, we can decide if we want to
			// pull this model into our own cache, rebroadcast it, or ignore it.

			remoteLogger.Info("Successfully processed record", "meta", meta, "labels", strings.Join(labels, ", "), "peer", notif.Peer.ID)
		}
	}
}
