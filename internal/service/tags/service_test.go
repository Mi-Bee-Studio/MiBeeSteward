package tags

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

func newSvc(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return New(db.New(conn)), conn
}

func TestSeedBuiltins_Idempotent(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	_ = svc

	require.NoError(t, svc.SeedBuiltins(ctx))
	require.NoError(t, svc.SeedBuiltins(ctx)) // second startup is a no-op

	all, err := svc.List(ctx)
	require.NoError(t, err)
	require.Len(t, all, 4, "exactly the four built-in seeds")
	keys := []string{all[0].Key, all[1].Key, all[2].Key, all[3].Key}
	require.Equal(t, []string{"internal", "external", "temporary", "pending"}, keys)
	for _, tag := range all {
		require.Equal(t, int64(1), tag.Builtin)
	}
}

func TestCreateValidation(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()

	_, err := svc.Create(ctx, "Bad Key!", "", "", "", 0)
	require.ErrorIs(t, err, ErrInvalidKey)
	_, err = svc.Create(ctx, "visitor", "", "", "", 0)
	require.NoError(t, err)
	// Duplicate key.
	_, err = svc.Create(ctx, "visitor", "", "", "", 0)
	require.ErrorIs(t, err, ErrDuplicateKey)
}

func TestDelete_BuiltinProtected(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	require.NoError(t, svc.SeedBuiltins(ctx))

	internal, err := svc.GetTagByKey(ctx, "internal")
	require.NoError(t, err)
	require.ErrorIs(t, svc.Delete(ctx, internal.ID), ErrBuiltinProtected)

	custom, err := svc.Create(ctx, "visitor", "Visitor", "", "", 0)
	require.NoError(t, err)
	require.NoError(t, svc.Delete(ctx, custom.ID))
}

func TestAssignAndBulk(t *testing.T) {
	svc, conn := newSvc(t)
	ctx := context.Background()
	require.NoError(t, svc.SeedBuiltins(ctx))

	dev := func(name string) int64 {
		res, err := conn.ExecContext(ctx, `INSERT INTO devices (device_uuid, name, type, tags) VALUES (?, ?, 'other', '{}')`,
			name+"-uuid", name)
		require.NoError(t, err)
		id, _ := res.LastInsertId()
		return id
	}
	d1, d2, d3 := dev("d1"), dev("d2"), dev("d3")

	external, err := svc.GetTagByKey(ctx, "external")
	require.NoError(t, err)

	// Bulk: two devices at once (the visitor-phone batch path).
	n, err := svc.AddToDevices(ctx, external.ID, []int64{d1, d2})
	require.NoError(t, err)
	require.Equal(t, 2, n)

	// Replace semantics: d3 gets exactly [external, temporary].
	temporary, err := svc.GetTagByKey(ctx, "temporary")
	require.NoError(t, err)
	require.NoError(t, svc.ReplaceDeviceTags(ctx, d3, []int64{external.ID, temporary.ID}))
	got, err := svc.ListForDevice(ctx, d3)
	require.NoError(t, err)
	require.Len(t, got, 2)

	// Batch fill for the list view.
	briefs, err := svc.FillForDevices(ctx, []int64{d1, d2, d3})
	require.NoError(t, err)
	require.Len(t, briefs[d1], 1)
	require.Len(t, briefs[d3], 2)
	require.False(t, briefs[d1][0].Builtin == false, "external is a built-in")
}
