// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//nolint:revive
package rpc

import (
	"context"
	"errors"

	corev1 "github.com/agntcy/dir/api/core/v1"
	routingtypes "github.com/agntcy/dir/api/routing/v1alpha2"
	"github.com/agntcy/dir/server/types"
	"github.com/agntcy/dir/utils/logging"
	rpc "github.com/libp2p/go-libp2p-gorpc"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var logger = logging.Logger("rpc")

// TODO: proper cleanup and implementation needed!

const (
	Protocol             = protocol.ID("/dir/rpc/1.0.0")
	DirService           = "RPCAPI"
	DirServiceFuncLookup = "Lookup"
	DirServiceFuncPull   = "Pull"
	DirServiceFuncList   = "List"
	MaxPullSize          = 4 * 1024 * 1024 // 4 MB
)

type RPCAPI struct {
	service *Service
}

type PullResponse struct {
	Cid         string
	Size        uint64
	Annotations map[string]string
	Data        []byte
}

type LookupResponse struct {
	Cid         string
	Size        uint64
	Annotations map[string]string
}

type ListRequest struct {
	Peer   string
	Labels []string
}

type ListResponse struct {
	Labels      []string
	LabelCounts map[string]uint64
	Peer        string
	Cid         string
	Size        uint64
	Annotations map[string]string
}

func (r *RPCAPI) Lookup(ctx context.Context, in *corev1.RecordRef, out *LookupResponse) error {
	logger.Debug("P2p RPC: Executing Lookup request on remote peer", "peer", r.service.host.ID())

	// validate request
	if in == nil || out == nil {
		return status.Error(codes.InvalidArgument, "invalid request: nil request/response") //nolint:wrapcheck
	}

	// handle lookup - get the full record
	record, err := r.service.store.Pull(ctx, in)
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "failed to lookup: %s", st.Message())
	}

	// calculate record size from marshaled protobuf data
	recordBytes, err := proto.Marshal(record)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal record for size calculation: %v", err)
	}

	// write result
	*out = LookupResponse{
		Cid:         record.GetCid(),
		Size:        uint64(len(recordBytes)),
		Annotations: map[string]string{}, // TODO: get annotations from record data
	}

	return nil
}

func (r *RPCAPI) Pull(ctx context.Context, in *corev1.RecordRef, out *PullResponse) error {
	logger.Debug("P2p RPC: Executing Pull request on remote peer", "peer", r.service.host.ID())

	// validate request
	if in == nil || out == nil {
		return status.Error(codes.InvalidArgument, "invalid request: nil request/response") //nolint:wrapcheck
	}

	// pull record directly
	record, err := r.service.store.Pull(ctx, in)
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "failed to pull: %s", st.Message())
	}

	// validate record type - check if it contains agent data
	if record.GetV1Alpha1() == nil && record.GetV1Alpha2() == nil {
		return status.Errorf(codes.Internal, "can only pull agent records")
	}

	// marshal record data using protobuf for consistency with CID calculation
	recordBytes, err := proto.Marshal(record)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal record: %v", err)
	}

	if uint64(len(recordBytes)) > MaxPullSize {
		return status.Errorf(codes.Internal, "record too large to pull: %d bytes", len(recordBytes))
	}

	// set output
	*out = PullResponse{
		Cid:         record.GetCid(),
		Size:        uint64(len(recordBytes)),
		Data:        recordBytes,
		Annotations: map[string]string{}, // TODO: get annotations from record data
	}

	return nil
}

func (r *RPCAPI) List(ctx context.Context, inCh <-chan *ListRequest, outCh chan<- *ListResponse) error {
	defer close(outCh)

	for in := range inCh {
		logger.Debug("P2p RPC: Executing List request on remote peer", "peer", r.service.host.ID())

		// convert labels to queries
		queries := make([]*routingtypes.RecordQuery, len(in.Labels))
		for i, label := range in.Labels {
			queries[i] = &routingtypes.RecordQuery{
				Type:  routingtypes.RecordQueryType_RECORD_QUERY_TYPE_SKILL, // assume skills for now
				Value: label,
			}
		}

		// local list
		listCh, err := r.service.route.List(ctx, &routingtypes.ListRequest{
			Queries: queries,
		})
		if err != nil {
			st := status.Convert(err)

			return status.Errorf(st.Code(), "failed to list: %s", st.Message())
		}

		// resolve response before forwarding
		for item := range listCh {
			result := &ListResponse{
				Labels:      in.Labels,                    // return original labels for compatibility
				LabelCounts: map[string]uint64{},          // TODO: calculate label counts if needed
				Peer:        r.service.host.ID().String(), // remote peer where local list was called
			}

			if recordRef := item.GetRecordRef(); recordRef != nil {
				result.Annotations = map[string]string{} // TODO: get annotations from record
				result.Size = 0                          // TODO: calculate size if needed
				result.Cid = recordRef.GetCid()
			}

			// forward data
			outCh <- result
		}
	}

	return nil
}

type Service struct {
	rpcServer *rpc.Server
	rpcClient *rpc.Client
	host      host.Host
	store     types.StoreAPI
	route     types.RoutingAPI
}

func New(host host.Host, store types.StoreAPI, route types.RoutingAPI) (*Service, error) {
	service := &Service{
		rpcServer: rpc.NewServer(host, Protocol),
		host:      host,
		store:     store,
		route:     route,
	}

	// register api
	rpcAPI := RPCAPI{service: service}

	err := service.rpcServer.Register(&rpcAPI)
	if err != nil {
		return nil, err //nolint:wrapcheck
	}

	// update client
	service.rpcClient = rpc.NewClientWithServer(host, Protocol, service.rpcServer)

	return service, nil
}

func (s *Service) Lookup(ctx context.Context, peer peer.ID, req *corev1.RecordRef) (*corev1.RecordRef, error) {
	logger.Debug("P2p RPC: Executing Lookup request on remote peer", "peer", peer, "req", req)

	var resp LookupResponse

	err := s.rpcClient.CallContext(ctx, peer, DirService, DirServiceFuncLookup, req, &resp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to call remote peer: %v", err)
	}

	return &corev1.RecordRef{
		Cid: resp.Cid,
	}, nil
}

func (s *Service) Pull(ctx context.Context, peer peer.ID, req *corev1.RecordRef) (*corev1.Record, error) {
	logger.Debug("P2p RPC: Executing Pull request on remote peer", "peer", peer, "req", req)

	var resp PullResponse

	err := s.rpcClient.CallContext(ctx, peer, DirService, DirServiceFuncPull, req, &resp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to call remote peer: %v", err)
	}

	// unmarshal protobuf data to record
	var record corev1.Record
	if err := proto.Unmarshal(resp.Data, &record); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unmarshal record data: %v", err)
	}

	return &record, nil
}

// range over the result channel, then read the error after the loop.
// this is done in best effort mode.
//
//nolint:mnd
func (s *Service) List(ctx context.Context, peers []peer.ID, req *routingtypes.ListRequest) (<-chan *corev1.RecordRef, error) {
	logger.Debug("P2p RPC: Executing List request on remote peers", "peers", peers, "req", req)

	// reserve reasonable buffer size for output results
	respCh := make(chan *corev1.RecordRef, 10000)

	// run processing in the background
	outCh := make(chan *ListResponse, 10000) // used as intermediary forwarding channel
	go func() {
		// run logic in the background
		// prepare inputs for each call
		inCh := make(chan *ListRequest, len(peers)+1)

		// convert queries back to labels for compatibility with internal RPC
		labels := make([]string, len(req.GetQueries()))
		for i, query := range req.GetQueries() {
			labels[i] = query.GetValue()
		}

		for _, peer := range peers {
			inCh <- &ListRequest{
				Peer:   peer.String(),
				Labels: labels,
			}
		}

		close(inCh)

		// run async
		errs := s.rpcClient.MultiStream(ctx,
			peers,
			DirService,
			DirServiceFuncList,
			inCh,
			outCh,
		)

		// log error
		if err := errors.Join(errs...); err != nil {
			logger.Error("Failed to process all List RPC requests", "error", err)

			return
		}

		logger.Info("Successfully processed all List RPC requests", "peers", peers)
	}()

	// forward results from one goroutine to the output channel
	go func() {
		// close resp channel once done so the subscribers can finish
		defer close(respCh)

		// remove duplicate outputs to avoid redundant entries
		// this can happen when multiple peers are connected to the same peer that holds the object
		seenPeerAgents := make(map[string]struct{})

		// forward data to response channel
		for out := range outCh {
			uniqueKey := out.Peer + out.Cid

			// check if we have already seen this peer
			if _, ok := seenPeerAgents[uniqueKey]; ok {
				continue
			}

			seenPeerAgents[uniqueKey] = struct{}{}
			respCh <- &corev1.RecordRef{
				Cid: out.Cid,
			}
		}
	}()

	return respCh, nil
}
