package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// DeviceRepository wraps sqlc queries for device operations.
type DeviceRepository struct {
	queries *db.Queries
	dbConn  db.DBTX // raw connection for the flexible ListFiltered query (sqlc can't express dynamic ORDER BY)
}

// NewDeviceRepository creates a new DeviceRepository.
func NewDeviceRepository(dbConn db.DBTX) *DeviceRepository {
	return &DeviceRepository{queries: db.New(dbConn), dbConn: dbConn}
}

// Create inserts a new device.
func (r *DeviceRepository) Create(ctx context.Context, req domain.CreateDeviceRequest) (db.Device, error) {
	deviceType := req.Type
	if deviceType == "" {
		deviceType = string(domain.TypeOther)
	}

	tags := req.Tags
	if tags == "" {
		tags = "{}"
	}

	userAttrs, err := domain.MarshalUserAttributes(req.UserAttributes)
	if err != nil {
		return db.Device{}, fmt.Errorf("failed to marshal user_attributes: %w", err)
	}

	device, err := r.queries.CreateDevice(ctx, db.CreateDeviceParams{
		Name:           req.Name,
		Type:           deviceType,
		Brand:          req.Brand,
		Model:          req.Model,
		Location:       req.Location,
		Purpose:        req.Purpose,
		Description:    req.Description,
		Status:         string(domain.StatusUnknown),
		IpAddress:      req.IPAddress,
		MacAddress:     req.MACAddress,
		SerialNumber:   req.SerialNumber,
		PurchaseDate:   req.PurchaseDate,
		WarrantyExpiry: req.WarrantyExpiry,
		Tags:           tags,
		UserAttributes: userAttrs,
	})
	if err != nil {
		return db.Device{}, fmt.Errorf("failed to create device: %w", err)
	}
	return device, nil
}

// UpdateUserAttributes replaces the user_attributes JSON document for a device.
func (r *DeviceRepository) UpdateUserAttributes(ctx context.Context, id int64, attrs domain.UserAttributes) error {
	raw, err := domain.MarshalUserAttributes(attrs)
	if err != nil {
		return fmt.Errorf("failed to marshal user_attributes: %w", err)
	}
	return r.queries.UpdateUserAttributes(ctx, db.UpdateUserAttributesParams{
		UserAttributes: raw,
		ID:             id,
	})
}

// UpdateScanAttributes replaces the engine-owned scan_attributes JSON
// document for a device. Only the scanner engine should call this.
func (r *DeviceRepository) UpdateScanAttributes(ctx context.Context, id int64, attrs domain.ScanAttributes) error {
	raw, err := domain.MarshalScanAttributes(attrs)
	if err != nil {
		return fmt.Errorf("failed to marshal scan_attributes: %w", err)
	}
	return r.queries.UpdateScanAttributes(ctx, db.UpdateScanAttributesParams{
		ScanAttributes: raw,
		ID:             id,
	})
}

// GetByMAC looks up a device by its normalized scan MAC via the scan_attributes
// JSON field (covered by idx_devices_scan_mac_expr). Returns the device and
// whether a match existed.
func (r *DeviceRepository) GetByMAC(ctx context.Context, mac string) (db.Device, bool, error) {
	if mac == "" {
		return db.Device{}, false, nil
	}
	device, err := r.queries.GetDeviceByMAC(ctx, mac)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return db.Device{}, false, nil
		}
		return db.Device{}, false, fmt.Errorf("failed to get device by MAC: %w", err)
	}
	return device, true, nil
}

// GetByID retrieves a device by its ID.
func (r *DeviceRepository) GetByID(ctx context.Context, id int64) (db.Device, error) {
	device, err := r.queries.GetDevice(ctx, id)
	if err != nil {
		return db.Device{}, fmt.Errorf("failed to get device: %w", err)
	}
	return device, nil
}

// List returns devices matching the filter with pagination.
func (r *DeviceRepository) List(ctx context.Context, filter domain.DeviceFilter) ([]db.Device, error) {
	statusVal := ""
	if filter.Status != "" {
		statusVal = filter.Status
	}

	typeVal := ""
	if filter.Type != "" {
		typeVal = filter.Type
	}

	devices, err := r.queries.ListDevices(ctx, db.ListDevicesParams{
		Column1: statusVal,
		Status:  statusVal,
		Column3: typeVal,
		Type:    typeVal,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}
	return devices, nil
}

// Count returns total device count matching the filter.
func (r *DeviceRepository) Count(ctx context.Context, filter domain.DeviceFilter) (int64, error) {
	statusVal := ""
	if filter.Status != "" {
		statusVal = filter.Status
	}

	typeVal := ""
	if filter.Type != "" {
		typeVal = filter.Type
	}

	count, err := r.queries.CountDevices(ctx, db.CountDevicesParams{
		Column1: statusVal,
		Status:  statusVal,
		Column3: typeVal,
		Type:    typeVal,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to count devices: %w", err)
	}
	return count, nil
}

// Update modifies an existing device.
func (r *DeviceRepository) Update(ctx context.Context, params db.UpdateDeviceParams) (db.Device, error) {
	device, err := r.queries.UpdateDevice(ctx, params)
	if err != nil {
		return db.Device{}, fmt.Errorf("failed to update device: %w", err)
	}
	return device, nil
}

// Delete removes a device by ID.
func (r *DeviceRepository) Delete(ctx context.Context, id int64) error {
	affected, err := r.queries.DeleteDevice(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete device: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("device not found")
	}
	return nil
}

// CountByStatus returns device counts grouped by status.
func (r *DeviceRepository) CountByStatus(ctx context.Context) ([]db.CountByStatusRow, error) {
	rows, err := r.queries.CountByStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count devices by status: %w", err)
	}
	return rows, nil
}

// CountByType returns device counts grouped by type.
func (r *DeviceRepository) CountByType(ctx context.Context) ([]db.CountDevicesByTypeRow, error) {
	rows, err := r.queries.CountDevicesByType(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count devices by type: %w", err)
	}
	return rows, nil
}

// CountByStatusForNetwork returns device counts grouped by status, scoped to a
// single network. networkID=nil disables the filter (all networks). Used by the
// dashboard's per-LAN stats.
func (r *DeviceRepository) CountByStatusForNetwork(ctx context.Context, networkID *int64) ([]db.CountByStatusForNetworkRow, error) {
	rows, err := r.queries.CountByStatusForNetwork(ctx, db.CountByStatusForNetworkParams{
		Column1:   networkID != nil, // 1 enables the filter, 0 disables
		NetworkID: networkID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to count devices by status (network): %w", err)
	}
	return rows, nil
}

// CountByTypeForNetwork returns device counts grouped by type, scoped to a
// single network. networkID=nil disables the filter.
func (r *DeviceRepository) CountByTypeForNetwork(ctx context.Context, networkID *int64) ([]db.CountDevicesByTypeForNetworkRow, error) {
	rows, err := r.queries.CountDevicesByTypeForNetwork(ctx, db.CountDevicesByTypeForNetworkParams{
		Column1:   networkID != nil,
		NetworkID: networkID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to count devices by type (network): %w", err)
	}
	return rows, nil
}

// sortWhitelist maps a client-supplied sort token to the real column name. Any
// token not in this map falls back to "id". This is the SQL-injection guard:
// only these literals ever reach ORDER BY, never raw user input.
var sortWhitelist = map[string]string{
	"id":              "id",
	"name":            "name",
	"ip_address":      "ip_address",
	"status":          "status",
	"type":            "type",
	"last_scanned_at": "last_scanned_at",
	"created_at":      "created_at",
}

// escapeLike escapes the SQL LIKE wildcards (\, %, _) in a search term so a
// user searching for a literal "10.0.0.1" or a name containing "_" matches the
// text itself. Caller selects the escape char via ESCAPE '\'.
func escapeLike(s string) string {
	out := make([]byte, 0, len(s)+4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' || c == '%' || c == '_' {
			out = append(out, '\\')
		}
		out = append(out, c)
	}
	return string(out)
}

// ListFiltered is the flexible device list used by the device page: server-side
// search (name/ip/mac/serial LIKE), created_at range, and a whitelisted sort.
// It intentionally lives outside sqlc — sqlc cannot express a dynamic ORDER BY,
// and the device list is the one query that genuinely needs per-request
// sorting. The sort column is taken from sortWhitelist (never raw input), and
// the search term is parameterized with ESCAPE, so there is no injection surface.
func (r *DeviceRepository) ListFiltered(ctx context.Context, f domain.DeviceFilter) ([]DeviceWithNetwork, error) {
	col := sortWhitelist[f.SortBy]
	if col == "" {
		col = "id"
	}
	dir := "ASC"
	if f.Order == "desc" {
		dir = "DESC"
	}
	// Runs outside a transaction; for a snapshot-consistent list+count pair use
	// ListFilteredWithCount instead.
	return listFilteredOn(ctx, r.dbConn, f, col, dir)
}

// CountFiltered mirrors ListFiltered's WHERE so the page total reflects the
// active search/range filters (the old CountDevices ignored search entirely,
// so filtered totals were wrong).
//
// Runs outside a transaction; for a snapshot-consistent list+count pair use
// ListFilteredWithCount instead.
func (r *DeviceRepository) CountFiltered(ctx context.Context, f domain.DeviceFilter) (int64, error) {
	return countFilteredOn(ctx, r.dbConn, f)
}

func strPtr(s string) *string { return &s }

// ListFilteredWithCount runs the filtered list query and the matching count in
// a single read transaction so both see the same snapshot.
//
// Why: ListFiltered + CountFiltered used to be two independent queries against
// the connection pool, which under WAL can land on two different connections
// and observe two different snapshots. The devices table is written to every
// ~30-60s (heartbeat status sync) and in bursts during scans, so a device
// insert/status change landing between the two queries made the page list and
// its total disagree — the visible symptom was the page count flapping on
// refresh (sometimes 2 pages, sometimes 5). Running both inside one
// read-only tx (BEGIN ... COMMIT) pins them to one snapshot. The tx is opened
// read-only so it never blocks writers and is eligible for WAL's concurrent
// reader optimization.
//
// It returns the device page and the total matching the filter.
func (r *DeviceRepository) ListFilteredWithCount(ctx context.Context, f domain.DeviceFilter) ([]DeviceWithNetwork, int64, error) {
	// Resolve sort column once (shared by list + the tx wrapper).
	col := sortWhitelist[f.SortBy]
	if col == "" {
		col = "id"
	}
	dir := "ASC"
	if f.Order == "desc" {
		dir = "DESC"
	}

	tx, err := r.dbConnAsDB().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, fmt.Errorf("begin read tx for list+count: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // safe to roll back a committed tx (no-op)

	list, err := listFilteredOn(ctx, tx, f, col, dir)
	if err != nil {
		return nil, 0, err
	}
	count, err := countFilteredOn(ctx, tx, f)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, fmt.Errorf("commit read tx for list+count: %w", err)
	}
	return list, count, nil
}

// dbConnAsDB unwraps the repository's dbConn to a *sql.DB for BeginTx.
// dbConn is typed as db.DBTX (the sqlc interface) to accept both *sql.DB and
// *sql.Tx, but in production it is always a *sql.DB (set in NewDeviceRepository
// from routes.go). This panics if someone wires a Tx in, which is desirable —
// we'd want to know.
func (r *DeviceRepository) dbConnAsDB() *sql.DB {
	if db, ok := r.dbConn.(*sql.DB); ok {
		return db
	}
	panic("DeviceRepository.dbConn is not a *sql.DB; ListFilteredWithCount requires a pool to open a read tx")
}

// listFilteredOn is the list query body parameterized over the DBTX it runs on,
// so it can execute inside the caller's read transaction.
// DeviceWithNetwork pairs a device row with its network's human name (resolved
// via LEFT JOIN on networks). NetworkName is "" when the device has no
// network_id (legacy/unresolved).
type DeviceWithNetwork struct {
	Device      db.Device
	NetworkName string
}

func listFilteredOn(ctx context.Context, q db.DBTX, f domain.DeviceFilter, col, dir string) ([]DeviceWithNetwork, error) {
	var (
		args           []any
		statusVal      = f.Status
		typeVal        = f.Type
		searchVal      = f.Search
		likeVal        = "%" + escapeLike(f.Search) + "%"
		createdFrom    string // "" disables the bound
		createdTo      string
		createdFromArg *string
	)
	if f.CreatedAtFrom != nil {
		createdFrom = "1"
		createdFromArg = strPtr(f.CreatedAtFrom.Format("2006-01-02 15:04:05"))
	}
	createdToArg := (*string)(nil)
	if f.CreatedAtTo != nil {
		createdTo = "1"
		createdToArg = strPtr(f.CreatedAtTo.Format("2006-01-02 15:04:05"))
	}
	// network filter: nil = no filter (all networks incl. NULL-network legacy);
	// non-nil = devices on that network only. 0 disables (matches all), 1 enables.
	networkFilterEnabled := 0
	var networkIDArg int64
	if f.NetworkID != nil {
		networkFilterEnabled = 1
		networkIDArg = *f.NetworkID
	}

	query := `SELECT d.id, d.name, d.type, d.brand, d.model, d.location, d.purpose, d.description, d.status, d.ip_address,
		d.mac_address, d.serial_number, d.purchase_date, d.warranty_expiry, d.tags, d.scan_source, d.prometheus_labels,
		d.last_scanned_at, d.last_scan_task_id, d.open_ports, d.detected_services, d.prometheus_url, d.node_exporter_url,
		d.last_scan_rtt_ms, d.scan_attributes, d.user_attributes, d.scan_vendor, d.scan_mac, d.scan_os, d.scan_hostname,
		d.network_id, d.first_seen, d.last_seen,
		d.created_at, d.updated_at,
		n.name
	FROM devices d
	LEFT JOIN networks n ON n.id = d.network_id
	WHERE (? = '' OR d.status = ?)
	  AND (? = '' OR d.type = ?)
	  AND (? = '' OR d.name LIKE ? ESCAPE '\' OR d.ip_address LIKE ? ESCAPE '\' OR d.mac_address LIKE ? ESCAPE '\' OR d.serial_number LIKE ? ESCAPE '\')
	  AND (? = '' OR d.created_at >= ?)
	  AND (? = '' OR d.created_at <= ?)
	  AND (? = 0 OR d.network_id = ?)
	ORDER BY d.` + col + " " + dir + `
	LIMIT ? OFFSET ?`

	args = append(args,
		statusVal, statusVal,
		typeVal, typeVal,
		searchVal, likeVal, likeVal, likeVal, likeVal,
		createdFrom, createdFromArg,
		createdTo, createdToArg,
		networkFilterEnabled, networkIDArg,
		f.Limit, f.Offset,
	)

	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list devices (filtered): %w", err)
	}
	defer rows.Close()

	var out []DeviceWithNetwork
	for rows.Next() {
		var (
			d           db.Device
			networkName sql.NullString
		)
		if err := rows.Scan(
			&d.ID, &d.Name, &d.Type, &d.Brand, &d.Model, &d.Location, &d.Purpose, &d.Description, &d.Status, &d.IpAddress,
			&d.MacAddress, &d.SerialNumber, &d.PurchaseDate, &d.WarrantyExpiry, &d.Tags, &d.ScanSource, &d.PrometheusLabels,
			&d.LastScannedAt, &d.LastScanTaskID, &d.OpenPorts, &d.DetectedServices, &d.PrometheusUrl, &d.NodeExporterUrl,
			&d.LastScanRttMs, &d.ScanAttributes, &d.UserAttributes, &d.ScanVendor, &d.ScanMac, &d.ScanOs, &d.ScanHostname,
			&d.NetworkID, &d.FirstSeen, &d.LastSeen,
			&d.CreatedAt, &d.UpdatedAt,
			&networkName,
		); err != nil {
			return nil, fmt.Errorf("scan device row: %w", err)
		}
		out = append(out, DeviceWithNetwork{Device: d, NetworkName: networkName.String})
	}
	return out, rows.Err()
}

// countFilteredOn is the count query body parameterized over the DBTX it runs on.
func countFilteredOn(ctx context.Context, q db.DBTX, f domain.DeviceFilter) (int64, error) {
	var (
		args        []any
		statusVal   = f.Status
		typeVal     = f.Type
		searchVal   = f.Search
		likeVal     = "%" + escapeLike(f.Search) + "%"
		createdFrom string
		createdTo   string
	)
	createdFromArg := (*string)(nil)
	if f.CreatedAtFrom != nil {
		createdFrom = "1"
		createdFromArg = strPtr(f.CreatedAtFrom.Format("2006-01-02 15:04:05"))
	}
	createdToArg := (*string)(nil)
	if f.CreatedAtTo != nil {
		createdTo = "1"
		createdToArg = strPtr(f.CreatedAtTo.Format("2006-01-02 15:04:05"))
	}
	// network filter must mirror listFilteredOn exactly so the count matches.
	networkFilterEnabled := 0
	var networkIDArg int64
	if f.NetworkID != nil {
		networkFilterEnabled = 1
		networkIDArg = *f.NetworkID
	}

	query := `SELECT COUNT(*) FROM devices
	WHERE (? = '' OR status = ?)
	  AND (? = '' OR type = ?)
	  AND (? = '' OR name LIKE ? ESCAPE '\' OR ip_address LIKE ? ESCAPE '\' OR mac_address LIKE ? ESCAPE '\' OR serial_number LIKE ? ESCAPE '\')
	  AND (? = '' OR created_at >= ?)
	  AND (? = '' OR created_at <= ?)
	  AND (? = 0 OR network_id = ?)`

	args = append(args,
		statusVal, statusVal,
		typeVal, typeVal,
		searchVal, likeVal, likeVal, likeVal, likeVal,
		createdFrom, createdFromArg,
		createdTo, createdToArg,
		networkFilterEnabled, networkIDArg,
	)

	var count int64
	if err := q.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count devices (filtered): %w", err)
	}
	return count, nil
}
