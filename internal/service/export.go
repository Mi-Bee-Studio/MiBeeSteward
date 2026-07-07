package service

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"mibee-steward/internal/db"
)

const exportChunkSize = 1000

// ExportService handles data export for devices, heartbeat results, and audit logs.
type ExportService struct {
	db *db.Queries // main DB (devices, audit logs)
	hb *db.Queries // dedicated heartbeat store (heartbeat_results) — nil falls back to db
}

// NewExportService creates a new ExportService bound to the main DB.
// Heartbeat results are read from hb when set (the dedicated heartbeat store);
// if hb is nil, heartbeat export falls back to the main DB (legacy behavior).
func NewExportService(db *db.Queries, hb *db.Queries) *ExportService {
	return &ExportService{db: db, hb: hb}
}

// Devices streams all device data in the specified format (csv or json).
func (s *ExportService) Devices(ctx context.Context, format string, w io.Writer) error {
	headers := []string{"id", "name", "type", "status", "ip_address", "mac_address", "brand", "model", "location", "purpose", "description", "tags", "created_at", "updated_at"}

	if format == "json" {
		return s.streamJSON(ctx, w, func(offset int64) ([]map[string]interface{}, error) {
			rows, err := s.db.ListDevices(ctx, db.ListDevicesParams{
				Column1: "",
				Status:  "",
				Column3: "",
				Type:    "",
				Limit:   exportChunkSize,
				Offset:  offset,
			})
			if err != nil {
				return nil, err
			}
			result := make([]map[string]interface{}, len(rows))
			for i, d := range rows {
				result[i] = map[string]interface{}{
					"id":          d.ID,
					"name":        d.Name,
					"type":        d.Type,
					"status":      d.Status,
					"ip_address":  d.IpAddress,
					"mac_address": d.MacAddress,
					"brand":       d.Brand,
					"model":       d.Model,
					"location":    d.Location,
					"purpose":     d.Purpose,
					"description": d.Description,
					"tags":        d.Tags,
					"created_at":  d.CreatedAt.Format(time.RFC3339),
					"updated_at":  d.UpdatedAt.Format(time.RFC3339),
				}
			}
			return result, nil
		})
	}

	// Default: CSV
	return s.streamCSV(ctx, w, headers, func(offset int64) ([][]string, error) {
		rows, err := s.db.ListDevices(ctx, db.ListDevicesParams{
			Column1: "",
			Status:  "",
			Column3: "",
			Type:    "",
			Limit:   exportChunkSize,
			Offset:  offset,
		})
		if err != nil {
			return nil, err
		}
		result := make([][]string, len(rows))
		for i, d := range rows {
			result[i] = []string{
				strconv.FormatInt(d.ID, 10),
				d.Name,
				d.Type,
				d.Status,
				d.IpAddress,
				d.MacAddress,
				d.Brand,
				d.Model,
				d.Location,
				d.Purpose,
				d.Description,
				d.Tags,
				d.CreatedAt.Format(time.RFC3339),
				d.UpdatedAt.Format(time.RFC3339),
			}
		}
		return result, nil
	})
}

// HeartbeatResults streams heartbeat results for a device in the specified format.
func (s *ExportService) HeartbeatResults(ctx context.Context, deviceID int64, format string, w io.Writer) error {
	headers := []string{"id", "device_id", "config_id", "status", "latency_ms", "error_message", "checked_at"}

	// Read from the dedicated heartbeat store when wired; fall back to the main
	// DB for older deployments where the store isn't injected. The main DB's
	// heartbeat_results is a stale leftover (no longer written to after the
	// store migration), so without the store the export would dump frozen data.
	hq := s.hb
	if hq == nil {
		hq = s.db
	}
	// ListHeartbeatResultsByDevice's time filters use checked_at >= ? AND <= ?;
	// a zero time would wrongly bound the range, so open it wide.
	from := time.Unix(0, 0)
	to := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

	if format == "json" {
		return s.streamJSON(ctx, w, func(offset int64) ([]map[string]interface{}, error) {
			rows, err := hq.ListHeartbeatResultsByTimeRange(ctx, db.ListHeartbeatResultsByTimeRangeParams{
				DeviceID:    deviceID,
				CheckedAt:   from,
				CheckedAt_2: to,
				Limit:       exportChunkSize,
				Offset:      offset,
			})
			if err != nil {
				return nil, err
			}
			result := make([]map[string]interface{}, len(rows))
			for i, r := range rows {
				result[i] = map[string]interface{}{
					"id":            r.ID,
					"device_id":     r.DeviceID,
					"config_id":     r.ConfigID,
					"status":        r.Status,
					"latency_ms":    r.LatencyMs,
					"error_message": r.ErrorMessage,
					"checked_at":    r.CheckedAt.Format(time.RFC3339),
				}
			}
			return result, nil
		})
	}

	return s.streamCSV(ctx, w, headers, func(offset int64) ([][]string, error) {
		rows, err := hq.ListHeartbeatResultsByTimeRange(ctx, db.ListHeartbeatResultsByTimeRangeParams{
			DeviceID:    deviceID,
			CheckedAt:   from,
			CheckedAt_2: to,
			Limit:       exportChunkSize,
			Offset:      offset,
		})
		if err != nil {
			return nil, err
		}
		result := make([][]string, len(rows))
		for i, r := range rows {
			result[i] = []string{
				strconv.FormatInt(r.ID, 10),
				strconv.FormatInt(r.DeviceID, 10),
				strconv.FormatInt(r.ConfigID, 10),
				r.Status,
				strconv.FormatFloat(r.LatencyMs, 'f', -1, 64),
				r.ErrorMessage,
				r.CheckedAt.Format(time.RFC3339),
			}
		}
		return result, nil
	})
}

// AuditLogs streams audit logs in the specified format.
func (s *ExportService) AuditLogs(ctx context.Context, format string, w io.Writer) error {
	headers := []string{"id", "user_id", "action", "resource_type", "resource_id", "ip_address", "user_agent", "details", "created_at"}

	if format == "json" {
		return s.streamJSON(ctx, w, func(offset int64) ([]map[string]interface{}, error) {
			rows, err := s.db.ListAuditLogs(ctx, db.ListAuditLogsParams{
				Column1:      0,
				UserID:       nil,
				Column3:      "",
				Action:       "",
				Column5:      "",
				ResourceType: "",
				Column7:      "",
				CreatedAt:    nil,
				Column9:      "",
				CreatedAt_2:  nil,
				Limit:        exportChunkSize,
				Offset:       offset,
			})
			if err != nil {
				return nil, err
			}
			result := make([]map[string]interface{}, len(rows))
			for i, a := range rows {
				m := map[string]interface{}{
					"id":            a.ID,
					"user_id":       nilIfNil(a.UserID),
					"action":        a.Action,
					"resource_type": a.ResourceType,
					"resource_id":   nilIfNil(a.ResourceID),
					"ip_address":    nilIfNil(a.IpAddress),
					"user_agent":    nilIfNil(a.UserAgent),
					"details":       nilIfNil(a.Details),
					"created_at":    nilIfTimeNil(a.CreatedAt),
				}
				result[i] = m
			}
			return result, nil
		})
	}

	return s.streamCSV(ctx, w, headers, func(offset int64) ([][]string, error) {
		rows, err := s.db.ListAuditLogs(ctx, db.ListAuditLogsParams{
			Column1:      0,
			UserID:       nil,
			Column3:      "",
			Action:       "",
			Column5:      "",
			ResourceType: "",
			Column7:      "",
			CreatedAt:    nil,
			Column9:      "",
			CreatedAt_2:  nil,
			Limit:        exportChunkSize,
			Offset:       offset,
		})
		if err != nil {
			return nil, err
		}
		result := make([][]string, len(rows))
		for i, a := range rows {
			result[i] = []string{
				strconv.FormatInt(a.ID, 10),
				nilStr(a.UserID),
				a.Action,
				a.ResourceType,
				nilStr(a.ResourceID),
				nilStr(a.IpAddress),
				nilStr(a.UserAgent),
				nilStr(a.Details),
				nilTimeStr(a.CreatedAt),
			}
		}
		return result, nil
	})
}

// streamCSV writes data in CSV format with UTF-8 BOM, streaming chunks.
func (s *ExportService) streamCSV(ctx context.Context, w io.Writer, headers []string, fetch func(offset int64) ([][]string, error)) error {
	// Write UTF-8 BOM
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return fmt.Errorf("failed to write BOM: %w", err)
	}

	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()

	// Write header
	if err := csvWriter.Write(headers); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return err
	}

	var offset int64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		records, err := fetch(offset)
		if err != nil {
			return fmt.Errorf("failed to fetch records at offset %d: %w", offset, err)
		}

		for _, record := range records {
			if err := csvWriter.Write(record); err != nil {
				return fmt.Errorf("failed to write CSV record: %w", err)
			}
		}
		csvWriter.Flush()
		if err := csvWriter.Error(); err != nil {
			return err
		}

		if len(records) < exportChunkSize {
			break
		}
		offset += int64(len(records))
	}

	return nil
}

// streamJSON writes data as a streaming JSON array.
func (s *ExportService) streamJSON(ctx context.Context, w io.Writer, fetch func(offset int64) ([]map[string]interface{}, error)) error {
	encoder := json.NewEncoder(w)

	if _, err := w.Write([]byte("[")); err != nil {
		return fmt.Errorf("failed to write JSON opening bracket: %w", err)
	}

	var offset int64
	first := true
	for {
		select {
		case <-ctx.Done():
			// Close the array before returning
			_, _ = w.Write([]byte("]"))
			return ctx.Err()
		default:
		}

		records, err := fetch(offset)
		if err != nil {
			return fmt.Errorf("failed to fetch records at offset %d: %w", offset, err)
		}

		for _, record := range records {
			if !first {
				if _, err := w.Write([]byte(",")); err != nil {
					return fmt.Errorf("failed to write JSON comma: %w", err)
				}
			}
			if err := encoder.Encode(record); err != nil {
				return fmt.Errorf("failed to encode JSON record: %w", err)
			}
			first = false
		}

		if len(records) < exportChunkSize {
			break
		}
		offset += int64(len(records))
	}

	if _, err := w.Write([]byte("]")); err != nil {
		return fmt.Errorf("failed to write JSON closing bracket: %w", err)
	}

	return nil
}

// Helper functions for nullable fields.

func nilIfNil[T any](v *T) interface{} {
	if v == nil {
		return nil
	}
	return *v
}

func nilIfTimeNil(v *time.Time) interface{} {
	if v == nil {
		return nil
	}
	return v.Format(time.RFC3339)
}

func nilStr(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case *string:
		if val == nil {
			return ""
		}
		return *val
	case *int64:
		if val == nil {
			return ""
		}
		return strconv.FormatInt(*val, 10)
	case string:
		return val
	default:
		return fmt.Sprintf("%v", val)
	}
}

func nilTimeStr(v *time.Time) string {
	if v == nil {
		return ""
	}
	return v.Format(time.RFC3339)
}
