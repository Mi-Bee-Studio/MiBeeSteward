package agentwatch

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// recordingRecorder captures Record calls.
type recordingRecorder struct {
	events []changedetect.ChangeEvent
}

func (r *recordingRecorder) Record(_ context.Context, ev changedetect.ChangeEvent) {
	r.events = append(r.events, ev)
}

func seedAgent(t *testing.T, q *db.Queries, id string, lastReport time.Time) {
	t.Helper()
	err := q.UpsertAgentStatus(context.Background(), db.UpsertAgentStatusParams{
		AgentID: id, Version: "0.1.8", Hostname: id + "-host", LastReportAt: lastReport,
	})
	require.NoError(t, err)
}

func TestSweeper_OfflineAndRecoveryTransitions(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	q := db.New(conn)
	ctx := context.Background()

	rec := &recordingRecorder{}
	s := NewSweeper(q, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))

	staleAgent := "agent-lan-63"
	freshAgent := "agent-lan-62"

	// First sight with one stale + one fresh agent: adopted SILENTLY.
	seedAgent(t, q, staleAgent, time.Now().Add(-30*time.Minute))
	seedAgent(t, q, freshAgent, time.Now().Add(-1*time.Minute))
	s.sweep(ctx)
	require.Empty(t, rec.events)

	// Fresh agent goes stale → agent_offline once.
	old := time.Now().Add(-30 * time.Minute)
	require.NoError(t, q.UpsertAgentStatus(ctx, db.UpsertAgentStatusParams{
		AgentID: freshAgent, Version: "0.1.8", Hostname: "orangepi", LastReportAt: old,
	}))
	s.sweep(ctx)
	require.Len(t, rec.events, 1)
	assert.Equal(t, changedetect.ChangeTypeAgentOffline, rec.events[0].ChangeType)
	assert.Equal(t, changedetect.EntityTypeAgent, rec.events[0].EntityType)
	assert.Equal(t, freshAgent, rec.events[0].AgentID)
	after, ok := rec.events[0].After.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "orangepi", after["hostname"])

	// Still stale: no repeat.
	s.sweep(ctx)
	require.Len(t, rec.events, 1)

	// It reports again → agent_recovered.
	require.NoError(t, q.UpsertAgentStatus(ctx, db.UpsertAgentStatusParams{
		AgentID: freshAgent, Version: "0.1.8", Hostname: "orangepi", LastReportAt: time.Now(),
	}))
	s.sweep(ctx)
	require.Len(t, rec.events, 2)
	assert.Equal(t, changedetect.ChangeTypeAgentRecovered, rec.events[1].ChangeType)

	// The OTHER (long-stale) agent never emitted: its state was adopted at
	// first sight and hasn't transitioned since.
	for _, ev := range rec.events {
		assert.NotEqual(t, staleAgent, ev.AgentID)
	}
}

func TestSweeper_DeregisteredAgentStateDropped(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	q := db.New(conn)
	ctx := context.Background()

	rec := &recordingRecorder{}
	s := NewSweeper(q, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))

	gone := "agent-temp"
	seedAgent(t, q, gone, time.Now())
	s.sweep(ctx) // adopted: online

	// Agent disappears entirely (deregistered): state dropped, no event.
	_, err = conn.ExecContext(ctx, "DELETE FROM agent_status WHERE agent_id = ?", gone)
	require.NoError(t, err)
	s.sweep(ctx)
	require.Empty(t, rec.events)

	// It re-registers while stale: first sight again → silent adoption.
	seedAgent(t, q, gone, time.Now().Add(-30*time.Minute))
	s.sweep(ctx)
	require.Empty(t, rec.events)
}
