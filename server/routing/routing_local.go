// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	corev1 "github.com/agntcy/dir/api/core/v1"
	routingtypes "github.com/agntcy/dir/api/routing/v1alpha2"
	"github.com/agntcy/dir/server/types"
	"github.com/agntcy/dir/server/types/adapters"
	"github.com/agntcy/dir/utils/logging"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-datastore"
	"github.com/ipfs/go-datastore/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var localLogger = logging.Logger("routing/local")

// operations performed locally.
type routeLocal struct {
	store  types.StoreAPI
	dstore types.Datastore
}

func newLocal(store types.StoreAPI, dstore types.Datastore) *routeLocal {
	return &routeLocal{
		store:  store,
		dstore: dstore,
	}
}

func (r *routeLocal) Publish(ctx context.Context, record types.Record) error {
	localLogger.Debug("Called local routing's Publish method", "record", record)

	cid := record.GetCid()
	if cid == "" {
		return status.Errorf(codes.InvalidArgument, "invalid record: missing CID")
	}

	recordData := record.GetRecordData()
	if recordData == nil {
		return status.Errorf(codes.InvalidArgument, "invalid record: missing data")
	}

	metrics, err := loadMetrics(ctx, r.dstore)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to load metrics: %v", err)
	}

	batch, err := r.dstore.Batch(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create batch: %v", err)
	}

	// the key where we will save the record
	recordKey := datastore.NewKey("/agents/" + cid)

	// check if we have the record already
	// this is useful to avoid updating metrics and running the same operation multiple times
	recordExists, err := r.dstore.Has(ctx, recordKey)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to check if record exists: %v", err)
	}

	if recordExists {
		localLogger.Info("Skipping republish as record was already published", "cid", cid)

		return nil
	}

	// store record for later lookup
	if err := batch.Put(ctx, recordKey, nil); err != nil {
		return status.Errorf(codes.Internal, "failed to put record key: %v", err)
	}

	// keep track of all record labels
	labels := getLabels(record)
	for _, label := range labels {
		// Add key with cid
		recordLabelKey := fmt.Sprintf("%s/%s", label, cid)
		if err := batch.Put(ctx, datastore.NewKey(recordLabelKey), nil); err != nil {
			return status.Errorf(codes.Internal, "failed to put label key: %v", err)
		}

		metrics.increment(label)
	}

	err = batch.Commit(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to commit batch: %v", err)
	}

	// sync metrics
	err = metrics.update(ctx, r.dstore)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to update metrics: %v", err)
	}

	localLogger.Info("Successfully published record", "cid", cid)

	return nil
}

//nolint:cyclop
func (r *routeLocal) List(ctx context.Context, req *routingtypes.ListRequest) (<-chan *routingtypes.ListResponse, error) {
	localLogger.Debug("Called local routing's List method", "req", req)

	// dest to write the results on
	outCh := make(chan *routingtypes.ListResponse)

	// load metrics for the client
	metrics, err := loadMetrics(ctx, r.dstore)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load metrics: %v", err)
	}

	// if we sent an empty request, return stats for the current peer
	if req.GetQueries() == nil || len(req.GetQueries()) == 0 {
		go func(labels []string) {
			defer close(outCh)

			// For empty requests, we could return peer stats, but v1alpha2 doesn't support this
			// The v1alpha2 API is query-based, so we'll just close the channel
			localLogger.Debug("Empty query request, returning no results")
		}(metrics.labels())

		return outCh, nil
	}

	// Convert v1alpha2 queries to v1alpha1 style labels for existing datastore structure
	var labels []string
	for _, query := range req.GetQueries() {
		switch query.GetType() {
		case routingtypes.RecordQueryType_RECORD_QUERY_TYPE_SKILL:
			labels = append(labels, "/skills/"+query.GetValue())
		case routingtypes.RecordQueryType_RECORD_QUERY_TYPE_LOCATOR:
			labels = append(labels, "/locators/"+query.GetValue())
		default:
			localLogger.Debug("Unsupported query type, skipping", "type", query.GetType())
		}
	}

	// validate request
	if len(labels) == 0 {
		return nil, errors.New("no valid queries provided")
	}

	// get filters for not least common labels
	var filters []query.Filter

	leastCommonLabel := labels[0]
	for _, label := range labels {
		if metrics.Data[label].Total < metrics.Data[leastCommonLabel].Total {
			leastCommonLabel = label
		}
	}

	for _, label := range labels {
		if label != leastCommonLabel {
			filters = append(filters, &labelFilter{
				dstore: r.dstore,
				ctx:    ctx,
				label:  label,
			})
		}
	}

	// start query
	res, err := r.dstore.Query(ctx, query.Query{
		Prefix:  leastCommonLabel,
		Filters: filters,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to query datastore: %v", err)
	}

	// process items in the background, done in best effort mode
	go func() {
		defer close(outCh)

		processedRecordCids := make(map[string]struct{})

		for entry := range res.Next() {
			// read record CID from datastore key
			cid, err := getRecordCidFromKey(entry.Key)
			if err != nil {
				localLogger.Error("failed to get record CID", "error", err)

				return
			}

			if _, ok := processedRecordCids[cid]; ok {
				continue
			}

			processedRecordCids[cid] = struct{}{}

			// create record reference using CID
			recordRef := &corev1.RecordRef{
				Cid: cid,
			}

			// get record from store
			record, err := r.store.Pull(ctx, recordRef)
			if err != nil {
				localLogger.Error("failed to pull record", "error", err)

				continue
			}

			// create adapter to work with record
			adapter := adapters.NewRecordAdapter(record)

			// get labels for verification (optional - could be skipped for performance)
			recordLabels := getLabels(adapter)
			localLogger.Debug("Found record with labels", "cid", cid, "labels", recordLabels)

			// forward results back
			outCh <- &routingtypes.ListResponse{
				RecordRef: recordRef,
			}
		}
	}()

	return outCh, nil
}

func (r *routeLocal) Unpublish(ctx context.Context, record types.Record) error {
	localLogger.Debug("Called local routing's Unpublish method", "record", record)

	cid := record.GetCid()
	if cid == "" {
		return status.Errorf(codes.InvalidArgument, "invalid record: missing CID")
	}

	recordData := record.GetRecordData()
	if recordData == nil {
		return status.Errorf(codes.InvalidArgument, "invalid record: missing data")
	}

	// load metrics for the client
	metrics, err := loadMetrics(ctx, r.dstore)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to load metrics: %v", err)
	}

	batch, err := r.dstore.Batch(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create batch: %v", err)
	}

	// get record key and remove record
	recordKey := datastore.NewKey("/agents/" + cid)
	if err := batch.Delete(ctx, recordKey); err != nil {
		return status.Errorf(codes.Internal, "failed to delete record key: %v", err)
	}

	// keep track of all record labels
	labels := getLabels(record)

	for _, label := range labels {
		// Delete key with cid
		recordLabelKey := fmt.Sprintf("%s/%s", label, cid)
		if err := batch.Delete(ctx, datastore.NewKey(recordLabelKey)); err != nil {
			return status.Errorf(codes.Internal, "failed to delete label key: %v", err)
		}

		metrics.decrement(label)
	}

	err = batch.Commit(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to commit batch: %v", err)
	}

	// sync metrics
	err = metrics.update(ctx, r.dstore)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to update metrics: %v", err)
	}

	localLogger.Info("Successfully unpublished record", "cid", cid)

	return nil
}

func getRecordCidFromKey(k string) (string, error) {
	// Extract CID from datastore key
	cidString := path.Base(k)

	// Validate CID format using go-cid library
	_, err := cid.Parse(cidString)
	if err != nil {
		return "", fmt.Errorf("invalid CID format: %s", cidString)
	}

	return cidString, nil
}

var _ query.Filter = (*labelFilter)(nil)

//nolint:containedctx
type labelFilter struct {
	dstore types.Datastore
	ctx    context.Context

	label string
}

func (s *labelFilter) Filter(e query.Entry) bool {
	digest := path.Base(e.Key)
	has, _ := s.dstore.Has(s.ctx, datastore.NewKey(fmt.Sprintf("%s/%s", s.label, digest)))

	return has
}

func getAgentSkills(record types.Record) []string {
	recordData := record.GetRecordData()
	if recordData == nil {
		return nil
	}

	skills := recordData.GetSkills()
	result := make([]string, 0, len(skills))
	for _, skill := range skills {
		result = append(result, "/skills/"+skill.GetName())
	}

	return result
}

func getAgentDomains(record types.Record) []string {
	recordData := record.GetRecordData()
	if recordData == nil {
		return nil
	}

	prefix := "schema.oasf.agntcy.org/domains/"
	var domains []string

	for _, ext := range recordData.GetExtensions() {
		if strings.HasPrefix(ext.GetName(), prefix) {
			domain := ext.GetName()[len(prefix):]
			domains = append(domains, "/domains/"+domain)
		}
	}

	return domains
}

func getAgentFeatures(record types.Record) []string {
	recordData := record.GetRecordData()
	if recordData == nil {
		return nil
	}

	prefix := "schema.oasf.agntcy.org/features/"
	var features []string

	for _, ext := range recordData.GetExtensions() {
		if strings.HasPrefix(ext.GetName(), prefix) {
			feature := ext.GetName()[len(prefix):]
			features = append(features, "/features/"+feature)
		}
	}

	return features
}

func getLabels(record types.Record) []string {
	var labels []string

	// get agent skills
	skills := getAgentSkills(record)
	labels = append(labels, skills...)

	// get agent domains
	domains := getAgentDomains(record)
	labels = append(labels, domains...)

	// get agent features
	features := getAgentFeatures(record)
	labels = append(labels, features...)

	return labels
}
