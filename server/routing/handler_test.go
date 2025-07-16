// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//nolint:testifylint
package routing

import (
	"testing"
	"time"

	corev1 "github.com/agntcy/dir/api/core/v1"
	oasfv1alpha1 "github.com/agntcy/dir/api/oasf/v1alpha1"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a v1 Record from v1alpha1 Agent
func createRecordFromAgentForHandler(agent *oasfv1alpha1.Agent) *corev1.Record {
	return &corev1.Record{
		Data: &corev1.Record_V1Alpha1{
			V1Alpha1: agent,
		},
	}
}

// Testing 2 nodes, A -> B
// stores and announces an agent.
// A discovers it retrieves the key metadata from B.
func TestHandler(t *testing.T) {
	// Test data
	testAgent := &oasfv1alpha1.Agent{
		Skills: []*oasfv1alpha1.Skill{
			{CategoryName: toPtr("category1"), ClassName: toPtr("class1")},
		},
		Locators: []*oasfv1alpha1.Locator{
			{Type: "type1", Url: "url1"},
		},
	}

	// Create record from agent
	testRecord := createRecordFromAgentForHandler(testAgent)

	// create demo network
	firstNode := newTestServer(t, t.Context(), nil)
	secondNode := newTestServer(t, t.Context(), firstNode.remote.server.P2pAddrs())

	// wait for connection
	time.Sleep(2 * time.Second)
	<-firstNode.remote.server.DHT().RefreshRoutingTable()
	<-secondNode.remote.server.DHT().RefreshRoutingTable()

	// Push the record to the store (this will generate the CID)
	recordRef, err := secondNode.remote.storeAPI.Push(t.Context(), testRecord)
	assert.NoError(t, err)
	assert.NotNil(t, recordRef)

	// Parse the CID string to get the CID object for DHT operations
	digestCID, err := cid.Parse(recordRef.GetCid())
	assert.NoError(t, err)

	// announce the key
	err = secondNode.remote.server.DHT().Provide(t.Context(), digestCID, true)
	assert.NoError(t, err)

	// wait for sync
	time.Sleep(2 * time.Second)
	<-firstNode.remote.server.DHT().RefreshRoutingTable()
	<-secondNode.remote.server.DHT().RefreshRoutingTable()

	// check on first
	found := false

	peerCh := firstNode.remote.server.DHT().FindProvidersAsync(t.Context(), digestCID, 1)
	for peer := range peerCh {
		if peer.ID == secondNode.remote.server.Host().ID() {
			found = true

			break
		}
	}

	assert.True(t, found)
}
