package repository

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"mibee-steward/internal/domain"
)

// setupSortTestDB creates an in-memory DB with the devices + networks shape that
// listFilteredOn queries against (devices with the scan_* generated columns, a
// networks row for the LEFT JOIN). It returns a DeviceRepository ready to call
// ListFilteredWithCount. Callers seed devices via repo.Create + raw UPDATEs.
func setupSortTestDB(t *testing.T) (*DeviceRepository, *sql.DB) {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	_, err = conn.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_uuid TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'other',
			brand TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			location TEXT NOT NULL DEFAULT '',
			purpose TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'unknown',
			ip_address TEXT NOT NULL DEFAULT '',
			mac_address TEXT NOT NULL DEFAULT '',
			serial_number TEXT NOT NULL DEFAULT '',
			purchase_date TEXT NOT NULL DEFAULT '',
			warranty_expiry TEXT NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT '{}',
			scan_source TEXT NOT NULL DEFAULT 'manual',
			prometheus_labels TEXT NOT NULL DEFAULT '{}',
			last_scanned_at TIMESTAMP,
			last_scan_task_id INTEGER,
			open_ports TEXT NOT NULL DEFAULT '[]',
			detected_services TEXT NOT NULL DEFAULT '[]',
			prometheus_url TEXT NOT NULL DEFAULT '',
			node_exporter_url TEXT NOT NULL DEFAULT '',
			last_scan_rtt_ms INTEGER NOT NULL DEFAULT 0,
			scan_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(scan_attributes)),
			user_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(user_attributes)),
			scan_vendor   TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.vendor')) STORED,
			scan_mac      TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.mac')) STORED,
			scan_os       TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.os')) STORED,
			scan_hostname TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.hostname')) STORED,
			network_id INTEGER,
			first_seen TIMESTAMP,
			last_seen TIMESTAMP,
			offline_since TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS networks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			cidr TEXT NOT NULL DEFAULT '',
			site TEXT NOT NULL DEFAULT '',
			agent_id TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`)
	require.NoError(t, err)
	return NewDeviceRepository(conn), conn
}

// seedIPs inserts devices with the given IPv4 strings (created in the listed
// order, so id order == call order unless the test sorts).
func seedIPs(t *testing.T, repo *DeviceRepository, ips ...string) {
	t.Helper()
	ctx := context.Background()
	for _, ip := range ips {
		_, err := repo.Create(ctx, domain.CreateDeviceRequest{
			Name:      "d-" + ip,
			Type:      "pc",
			IPAddress: ip,
		})
		require.NoError(t, err)
	}
}

func ipsOf(rows []DeviceWithNetwork) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Device.IpAddress
	}
	return out
}

// TestListFiltered_IPSortIsNumericNotLexical is the regression guard for the
// IPv4-in-TEXT ordering bug: a lexical ORDER BY puts 192.168.0.10 before
// 192.168.0.9 ("1" < "9" at the 4th octet's first char). The zero-padded key
// fixes it so .9 precedes .10, and cross-prefix ordering (10.x < 172.x < 192.x)
// is correct too.
func TestListFiltered_IPSortIsNumericNotLexical(t *testing.T) {
	repo, _ := setupSortTestDB(t)
	seedIPs(t, repo,
		"192.168.0.10",
		"192.168.0.9",
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.2",
		"10.0.0.10",
	)

	rows, _, err := repo.ListFilteredWithCount(context.Background(), domain.DeviceFilter{
		SortBy: "ip_address",
		Order:  "asc",
		Limit:  100,
	})
	require.NoError(t, err)
	require.Equal(t,
		[]string{"10.0.0.1", "10.0.0.10", "172.16.0.2", "192.168.0.9", "192.168.0.10", "192.168.1.1"},
		ipsOf(rows),
		"IPv4 sort must be numeric (.9 before .10), not lexical",
	)

	// Descending reverses the same numeric order.
	rows, _, err = repo.ListFilteredWithCount(context.Background(), domain.DeviceFilter{
		SortBy: "ip_address",
		Order:  "desc",
		Limit:  100,
	})
	require.NoError(t, err)
	require.Equal(t,
		[]string{"192.168.1.1", "192.168.0.10", "192.168.0.9", "172.16.0.2", "10.0.0.10", "10.0.0.1"},
		ipsOf(rows),
	)
}

// TestListFiltered_NetworkNameSort covers the joined n.name column that the new
// whitelist entry exposes. Two networks + devices on each; sorting by network
// name groups devices by their network's human name.
func TestListFiltered_NetworkNameSort(t *testing.T) {
	repo, conn := setupSortTestDB(t)
	ctx := context.Background()

	// Two networks: "lan-b" (id 1) and "lan-a" (id 2). Seeded out of name order
	// so only a network_name sort (not id) would put lan-a first.
	_, err := conn.Exec(`INSERT INTO networks (id, name) VALUES (1, 'lan-b'), (2, 'lan-a')`)
	require.NoError(t, err)

	d1, err := repo.Create(ctx, domain.CreateDeviceRequest{Name: "on-b", IPAddress: "10.0.0.1"})
	require.NoError(t, err)
	d2, err := repo.Create(ctx, domain.CreateDeviceRequest{Name: "on-a", IPAddress: "10.0.0.2"})
	require.NoError(t, err)
	_, err = conn.Exec(`UPDATE devices SET network_id = 1 WHERE id = ?`, d1.ID)
	require.NoError(t, err)
	_, err = conn.Exec(`UPDATE devices SET network_id = 2 WHERE id = ?`, d2.ID)
	require.NoError(t, err)

	rows, _, err := repo.ListFilteredWithCount(ctx, domain.DeviceFilter{
		SortBy: "network_name",
		Order:  "asc",
		Limit:  100,
	})
	require.NoError(t, err)
	require.Len(t, rows, 2)
	require.Equal(t, "on-a", rows[0].Device.Name, "lan-a network should sort first")
	require.Equal(t, "on-b", rows[1].Device.Name)
}

// TestListFiltered_VendorHostnameSort covers the scan_vendor / scan_hostname
// generated columns exposed by the new whitelist entries.
func TestListFiltered_VendorHostnameSort(t *testing.T) {
	repo, conn := setupSortTestDB(t)
	ctx := context.Background()

	d1, err := repo.Create(ctx, domain.CreateDeviceRequest{Name: "z", IPAddress: "10.0.0.1"})
	require.NoError(t, err)
	d2, err := repo.Create(ctx, domain.CreateDeviceRequest{Name: "a", IPAddress: "10.0.0.2"})
	require.NoError(t, err)
	// vendor: "Zebra" on d1, "Alpha" on d2 → asc should put d2 first.
	_, err = conn.Exec(`UPDATE devices SET scan_attributes = json_set(scan_attributes, '$.vendor', 'Zebra', '$.hostname', 'host-z') WHERE id = ?`, d1.ID)
	require.NoError(t, err)
	_, err = conn.Exec(`UPDATE devices SET scan_attributes = json_set(scan_attributes, '$.vendor', 'Alpha', '$.hostname', 'host-a') WHERE id = ?`, d2.ID)
	require.NoError(t, err)

	rows, _, err := repo.ListFilteredWithCount(ctx, domain.DeviceFilter{
		SortBy: "vendor", Order: "asc", Limit: 100,
	})
	require.NoError(t, err)
	require.Equal(t, "a", rows[0].Device.Name, "vendor=Alpha should sort before Zebra")

	rows, _, err = repo.ListFilteredWithCount(ctx, domain.DeviceFilter{
		SortBy: "hostname", Order: "asc", Limit: 100,
	})
	require.NoError(t, err)
	require.Equal(t, "a", rows[0].Device.Name, "hostname=host-a should sort before host-z")
}

// TestListFiltered_DefaultSortByID verifies the fallback (unknown/empty sort key
// → ORDER BY d.id) still holds after the sort-expr refactor.
func TestListFiltered_DefaultSortByID(t *testing.T) {
	repo, _ := setupSortTestDB(t)
	seedIPs(t, repo, "192.168.0.10", "192.168.0.9", "10.0.0.1")

	rows, _, err := repo.ListFilteredWithCount(context.Background(), domain.DeviceFilter{
		Limit: 100, // no SortBy → default
	})
	require.NoError(t, err)
	// id order == insertion order; an unknown sort key must NOT reorder.
	require.Equal(t, []string{"192.168.0.10", "192.168.0.9", "10.0.0.1"}, ipsOf(rows))
}
