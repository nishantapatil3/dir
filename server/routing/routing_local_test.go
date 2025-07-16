// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// nolint:testifylint,wsl
package routing

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	corev1 "github.com/agntcy/dir/api/core/v1"
	oasfv1alpha1 "github.com/agntcy/dir/api/oasf/v1alpha1"
	routingtypes "github.com/agntcy/dir/api/routing/v1alpha2"
	"github.com/agntcy/dir/server/datastore"
	"github.com/agntcy/dir/server/types"
	"github.com/agntcy/dir/server/types/adapters"
	"github.com/agntcy/dir/utils/logging"
	ipfsdatastore "github.com/ipfs/go-datastore"
	"github.com/stretchr/testify/assert"
)

func TestPublish_InvalidObject(t *testing.T) {
	r := &routeLocal{}

	t.Run("Invalid object", func(t *testing.T) {
		// Create an invalid record with nil data
		invalidRecord := &corev1.Record{
			Data: nil, // Invalid - no data
		}
		adapter := adapters.NewRecordAdapter(invalidRecord)

		err := r.Publish(t.Context(), adapter)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "invalid record: missing data")
	})
}

type mockStore struct {
	data map[string]*corev1.Record
}

func newMockStore() *mockStore {
	return &mockStore{
		data: make(map[string]*corev1.Record),
	}
}

func (m *mockStore) Push(_ context.Context, record *corev1.Record) (*corev1.RecordRef, error) {
	if record.GetCid() == "" {
		return nil, errors.New("record missing CID")
	}

	m.data[record.GetCid()] = record

	return &corev1.RecordRef{
		Cid: record.GetCid(),
	}, nil
}

func (m *mockStore) Lookup(_ context.Context, ref *corev1.RecordRef) (*corev1.RecordMeta, error) {
	if record, exists := m.data[ref.GetCid()]; exists {
		return &corev1.RecordMeta{
			Cid: record.GetCid(),
		}, nil
	}

	return nil, errors.New("test record not found")
}

func (m *mockStore) Pull(_ context.Context, ref *corev1.RecordRef) (*corev1.Record, error) {
	if record, exists := m.data[ref.GetCid()]; exists {
		return record, nil
	}

	return nil, errors.New("test record not found")
}

func (m *mockStore) Delete(_ context.Context, ref *corev1.RecordRef) error {
	delete(m.data, ref.GetCid())
	return nil
}

// Helper function to create a v1 Record from v1alpha1 Agent
func createRecordFromAgent(agent *oasfv1alpha1.Agent) *corev1.Record {
	return &corev1.Record{
		Data: &corev1.Record_V1Alpha1{
			V1Alpha1: agent,
		},
	}
}

func TestPublishList_ValidSingleSkillQuery(t *testing.T) {
	var (
		testAgent = &oasfv1alpha1.Agent{
			Skills: []*oasfv1alpha1.Skill{
				{CategoryName: toPtr("category1"), ClassName: toPtr("class1")},
			},
		}
		testAgent2 = &oasfv1alpha1.Agent{
			Skills: []*oasfv1alpha1.Skill{
				{CategoryName: toPtr("category1"), ClassName: toPtr("class1")},
				{CategoryName: toPtr("category2"), ClassName: toPtr("class2")},
			},
		}

		testRecord  = createRecordFromAgent(testAgent)
		testRecord2 = createRecordFromAgent(testAgent2)

		validQueriesWithExpectedCids = map[string][]string{
			// tests exact lookup for skills
			"/skills/category1/class1": {
				testRecord.GetCid(),
				testRecord2.GetCid(),
			},
			// tests prefix based-lookup for skills
			"/skills/category2": {
				testRecord2.GetCid(),
			},
		}
	)

	// create demo network
	mainNode := newTestServer(t, t.Context(), nil)
	r := newTestServer(t, t.Context(), mainNode.remote.server.P2pAddrs())

	// wait for connection
	<-mainNode.remote.server.DHT().RefreshRoutingTable()
	time.Sleep(1 * time.Second)

	// Mock store
	mockstore := newMockStore()
	r.local.store = mockstore

	// Push records to store
	_, err := r.local.store.Push(t.Context(), testRecord)
	assert.NoError(t, err)

	_, err = r.local.store.Push(t.Context(), testRecord2)
	assert.NoError(t, err)

	// Publish first agent
	adapter1 := adapters.NewRecordAdapter(testRecord)
	err = r.Publish(t.Context(), adapter1)
	assert.NoError(t, err)

	// Publish second agent
	adapter2 := adapters.NewRecordAdapter(testRecord2)
	err = r.Publish(t.Context(), adapter2)
	assert.NoError(t, err)

	for queryStr, expectedCids := range validQueriesWithExpectedCids {
		t.Run("Valid query: "+queryStr, func(t *testing.T) {
			// Convert old label-style query to new RecordQuery format
			var queries []*routingtypes.RecordQuery
			if queryStr == "/skills/category1/class1" {
				queries = []*routingtypes.RecordQuery{
					{
						Type:  routingtypes.RecordQueryType_RECORD_QUERY_TYPE_SKILL,
						Value: "category1/class1",
					},
				}
			} else if queryStr == "/skills/category2" {
				queries = []*routingtypes.RecordQuery{
					{
						Type:  routingtypes.RecordQueryType_RECORD_QUERY_TYPE_SKILL,
						Value: "category2",
					},
				}
			}

			// list
			refsChan, err := r.List(t.Context(), &routingtypes.ListRequest{
				Queries: queries,
			})
			assert.NoError(t, err)

			// Collect items from the channel
			var refs []*routingtypes.ListResponse
			for ref := range refsChan {
				refs = append(refs, ref)
			}

			// check if expected refs are present
			assert.Len(t, refs, len(expectedCids))

			// check if all expected refs are present
			for _, expectedCid := range expectedCids {
				found := false

				for _, ref := range refs {
					if ref.GetRecordRef().GetCid() == expectedCid {
						found = true
						break
					}
				}

				assert.True(t, found, "Expected CID not found: %s", expectedCid)
			}
		})
	}

	// Unpublish second agent
	err = r.Unpublish(t.Context(), adapter2)
	assert.NoError(t, err)

	// Try to list second agent
	refsChan, err := r.List(t.Context(), &routingtypes.ListRequest{
		Queries: []*routingtypes.RecordQuery{
			{
				Type:  routingtypes.RecordQueryType_RECORD_QUERY_TYPE_SKILL,
				Value: "category2",
			},
		},
	})
	assert.NoError(t, err)

	// Collect items from the channel
	var refs []*routingtypes.ListResponse //nolint:prealloc
	for ref := range refsChan {
		refs = append(refs, ref)
	}

	// check no refs are present
	assert.Len(t, refs, 0)
}

func TestPublishList_ValidMultiSkillQuery(t *testing.T) {
	// Test data
	var (
		testAgent = &oasfv1alpha1.Agent{
			Skills: []*oasfv1alpha1.Skill{
				{CategoryName: toPtr("category1"), ClassName: toPtr("class1")},
				{CategoryName: toPtr("category2"), ClassName: toPtr("class2")},
			},
		}

		testRecord = createRecordFromAgent(testAgent)
	)

	// create demo network
	mainNode := newTestServer(t, t.Context(), nil)
	r := newTestServer(t, t.Context(), mainNode.remote.server.P2pAddrs())

	// wait for connection
	<-mainNode.remote.server.DHT().RefreshRoutingTable()
	time.Sleep(1 * time.Second)

	// Mock store
	mockstore := newMockStore()
	r.local.store = mockstore

	_, err := r.local.store.Push(t.Context(), testRecord)
	assert.NoError(t, err)

	// Publish first agent
	adapter := adapters.NewRecordAdapter(testRecord)
	err = r.Publish(t.Context(), adapter)
	assert.NoError(t, err)

	t.Run("Valid multi skill query", func(t *testing.T) {
		// list
		refsChan, err := r.List(t.Context(), &routingtypes.ListRequest{
			Queries: []*routingtypes.RecordQuery{
				{
					Type:  routingtypes.RecordQueryType_RECORD_QUERY_TYPE_SKILL,
					Value: "category1/class1",
				},
				{
					Type:  routingtypes.RecordQueryType_RECORD_QUERY_TYPE_SKILL,
					Value: "category2/class2",
				},
			},
		})
		assert.NoError(t, err)

		// Collect items from the channel
		var refs []*routingtypes.ListResponse
		for ref := range refsChan {
			refs = append(refs, ref)
		}

		// check if expected refs are present
		assert.Len(t, refs, 1)

		// check if expected ref is present
		assert.Equal(t, testRecord.GetCid(), refs[0].GetRecordRef().GetCid())
	})
}

func newBadgerDatastore(b *testing.B) types.Datastore {
	b.Helper()

	dsOpts := []datastore.Option{
		datastore.WithFsProvider("/tmp/test-datastore"), // Use a temporary directory
	}

	dstore, err := datastore.New(dsOpts...)
	if err != nil {
		b.Fatalf("failed to create badger datastore: %v", err)
	}

	b.Cleanup(func() {
		_ = dstore.Close()
		_ = os.RemoveAll("/tmp/test-datastore")
	})

	return dstore
}

func newInMemoryDatastore(b *testing.B) types.Datastore {
	b.Helper()

	dstore, err := datastore.New()
	if err != nil {
		b.Fatalf("failed to create in-memory datastore: %v", err)
	}

	return dstore
}

func Benchmark_RouteLocal(b *testing.B) {
	store := newMockStore()
	badgerDatastore := newBadgerDatastore(b)
	inMemoryDatastore := newInMemoryDatastore(b)
	localLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

	badgerRouter := newLocal(store, badgerDatastore)
	inMemoryRouter := newLocal(store, inMemoryDatastore)

	agent := &oasfv1alpha1.Agent{
		Skills: []*oasfv1alpha1.Skill{
			{CategoryName: toPtr("category1"), ClassName: toPtr("class1")},
		},
	}
	record := createRecordFromAgent(agent)
	adapter := adapters.NewRecordAdapter(record)

	_, err := store.Push(b.Context(), record)
	assert.NoError(b, err)

	b.Run("Badger DB Publish and Unpublish", func(b *testing.B) {
		for b.Loop() {
			_ = badgerRouter.Publish(b.Context(), adapter)
			err := badgerRouter.Unpublish(b.Context(), adapter)
			assert.NoError(b, err)
		}
	})

	b.Run("Badger DB List", func(b *testing.B) {
		_ = badgerRouter.Publish(b.Context(), adapter)
		for b.Loop() {
			_, err := badgerRouter.List(b.Context(), &routingtypes.ListRequest{
				Queries: []*routingtypes.RecordQuery{
					{
						Type:  routingtypes.RecordQueryType_RECORD_QUERY_TYPE_SKILL,
						Value: "category1/class1",
					},
				},
			})
			assert.NoError(b, err)
		}
	})

	b.Run("In memory DB Publish and Unpublish", func(b *testing.B) {
		for b.Loop() {
			_ = inMemoryRouter.Publish(b.Context(), adapter)
			err := inMemoryRouter.Unpublish(b.Context(), adapter)
			assert.NoError(b, err)
		}
	})

	b.Run("In memory DB List", func(b *testing.B) {
		_ = inMemoryRouter.Publish(b.Context(), adapter)
		for b.Loop() {
			_, err := inMemoryRouter.List(b.Context(), &routingtypes.ListRequest{
				Queries: []*routingtypes.RecordQuery{
					{
						Type:  routingtypes.RecordQueryType_RECORD_QUERY_TYPE_SKILL,
						Value: "category1/class1",
					},
				},
			})
			assert.NoError(b, err)
		}
	})

	_ = badgerDatastore.Delete(b.Context(), ipfsdatastore.NewKey("/"))   // Delete all keys
	_ = inMemoryDatastore.Delete(b.Context(), ipfsdatastore.NewKey("/")) // Delete all keys
	localLogger = logging.Logger("routing/local")
}
