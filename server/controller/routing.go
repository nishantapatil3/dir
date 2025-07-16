// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"

	corev1 "github.com/agntcy/dir/api/core/v1"
	routingtypes "github.com/agntcy/dir/api/routing/v1alpha2"
	"github.com/agntcy/dir/server/types"
	"github.com/agntcy/dir/server/types/adapters"
	"github.com/agntcy/dir/utils/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var routingLogger = logging.Logger("controller/routing")

type routingCtlr struct {
	routingtypes.UnimplementedRoutingServiceServer
	routing types.RoutingAPI
	store   types.StoreAPI
}

func NewRoutingController(routing types.RoutingAPI, store types.StoreAPI) routingtypes.RoutingServiceServer {
	return &routingCtlr{
		routing:                           routing,
		store:                             store,
		UnimplementedRoutingServiceServer: routingtypes.UnimplementedRoutingServiceServer{},
	}
}

func (c *routingCtlr) Publish(ctx context.Context, req *routingtypes.PublishRequest) (*routingtypes.PublishResponse, error) {
	routingLogger.Debug("Called routing controller's Publish method", "req", req)

	recordAdapter, err := c.getRecordAdapter(ctx, req.GetRecordRef())
	if err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "failed to get record: %s", st.Message())
	}

	err = c.routing.Publish(ctx, recordAdapter)
	if err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "failed to publish: %s", st.Message())
	}

	return &routingtypes.PublishResponse{}, nil
}

func (c *routingCtlr) List(req *routingtypes.ListRequest, srv routingtypes.RoutingService_ListServer) error {
	routingLogger.Debug("Called routing controller's List method", "req", req)

	itemChan, err := c.routing.List(srv.Context(), req)
	if err != nil {
		st := status.Convert(err)

		return status.Errorf(st.Code(), "failed to list: %s", st.Message())
	}

	for item := range itemChan {
		if err := srv.Send(item); err != nil {
			return status.Errorf(codes.Internal, "failed to send list response: %v", err)
		}
	}

	return nil
}

func (c *routingCtlr) Unpublish(ctx context.Context, req *routingtypes.UnpublishRequest) (*routingtypes.UnpublishResponse, error) {
	routingLogger.Debug("Called routing controller's Unpublish method", "req", req)

	recordAdapter, err := c.getRecordAdapter(ctx, req.GetRecordRef())
	if err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "failed to get record: %s", st.Message())
	}

	err = c.routing.Unpublish(ctx, recordAdapter)
	if err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "failed to unpublish: %s", st.Message())
	}

	return &routingtypes.UnpublishResponse{}, nil
}

func (c *routingCtlr) getRecordAdapter(ctx context.Context, ref *corev1.RecordRef) (types.Record, error) {
	routingLogger.Debug("Called routing controller's getRecordAdapter method", "ref", ref)

	if ref == nil || ref.GetCid() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "record reference is required and must have a CID")
	}

	// Pull the record directly - let the routing layer validate content
	record, err := c.store.Pull(ctx, ref)
	if err != nil {
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "failed to pull record: %s", st.Message())
	}

	routingLogger.Debug("Successfully retrieved record", "cid", ref.GetCid())

	// Create and return adapter directly
	return adapters.NewRecordAdapter(record), nil
}
