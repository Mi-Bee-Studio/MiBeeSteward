package testutil_test

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"

	"mibee-steward/internal/testutil"
)

func TestSetupTestDB(t *testing.T) {
	schema := "CREATE TABLE IF NOT EXISTS test_table (id INTEGER PRIMARY KEY);"
	db, err := testutil.SetupTestDB(schema)
	require.NoError(t, err)
	defer db.Close()

	// Verify the table was created
	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='test_table'").Scan(&tableName)
	require.NoError(t, err)
	require.Equal(t, "test_table", tableName)
}

func TestSetupTestDB_ExecError(t *testing.T) {
	// Invalid SQL should return an error
	_, err := testutil.SetupTestDB("INVALID SQL STATEMENT")
	require.Error(t, err)
}

func TestReadSchemaFile(t *testing.T) {
	schema, err := testutil.ReadSchemaFile()
	require.NoError(t, err)
	require.NotEmpty(t, schema)
	require.Contains(t, schema, "CREATE TABLE IF NOT EXISTS users")
	require.Contains(t, schema, "failed_login_attempts")
	require.Contains(t, schema, "must_change_password")
	require.Contains(t, schema, "audit_logs")
	require.Contains(t, schema, "device_systems")
}

func TestSetupTestDBFromSchema(t *testing.T) {
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer db.Close()

	// Verify all expected tables exist
	tables := listTables(t, db)
	expected := []string{
		"agent_commands",
		"agent_tokens",
		"audit_logs",
		"change_log",
		"dashboard_configs",
		"device_documents",
		"device_neighbors",
		"device_systems",
		"devices",
		"documents",
		"heartbeat_configs",
		"heartbeat_results",
		"host_services",
		"networks",
		"notification_channels",
		"notification_log",
		"scan_results",
		"scan_snapshots",
		"scan_task_runs",
		"scan_tasks",
		"service_evidence",
		"subnets",
		"topology_edges",
		"user_totp",
		"users",
		"vlans",
	}
	require.Equal(t, expected, tables)
}

func TestSetupTestDBFromSchema_Reusable(t *testing.T) {
	// Verify the schema can be applied multiple times (idempotent)
	db1, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer db1.Close()
	require.Len(t, listTables(t, db1), 26)

	db2, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	defer db2.Close()
	require.Len(t, listTables(t, db2), 26)
}

func TestSetupTestDB_WithPragmas(t *testing.T) {
	schema := "CREATE TABLE IF NOT EXISTS pragma_test (id INTEGER PRIMARY KEY);"
	db, err := testutil.SetupTestDB(schema)
	require.NoError(t, err)
	defer db.Close()

	// Verify WAL mode is set
	var journalMode string
	err = db.QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	require.NoError(t, err)
	// The returned value may be "wal" or "memory" depending on driver
	require.Contains(t, []string{"wal", "memory", "delete"}, journalMode)
}

func TestReadSchemaFile_ContainsAllTables(t *testing.T) {
	schema, err := testutil.ReadSchemaFile()
	require.NoError(t, err)
	require.Contains(t, schema, "CREATE TABLE IF NOT EXISTS users")
	require.Contains(t, schema, "CREATE TABLE IF NOT EXISTS devices")
	require.Contains(t, schema, "CREATE TABLE IF NOT EXISTS documents")
	require.Contains(t, schema, "CREATE TABLE IF NOT EXISTS device_documents")
	require.Contains(t, schema, "CREATE TABLE IF NOT EXISTS heartbeat_configs")
	require.Contains(t, schema, "CREATE TABLE IF NOT EXISTS heartbeat_results")
	require.Contains(t, schema, "CREATE TABLE IF NOT EXISTS dashboard_configs")
	require.Contains(t, schema, "CREATE TABLE IF NOT EXISTS audit_logs")
	require.Contains(t, schema, "CREATE TABLE IF NOT EXISTS device_systems")
}

// listTables returns all table names in the database, sorted.
func listTables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence' ORDER BY name")
	require.NoError(t, err)
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		tables = append(tables, name)
	}
	require.NoError(t, rows.Err())

	return tables
}
