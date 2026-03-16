package sqlcdb

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Queries is a typed SQL query wrapper that mirrors upcoming sqlc-generated methods.
type Queries struct {
	db *sql.DB
}

func New(db *sql.DB) *Queries {
	return &Queries{db: db}
}

type ScanRow struct {
	ID           string
	Provider     string
	Status       string
	StartedAt    time.Time
	FinishedAt   *time.Time
	AssetCount   int
	FindingCount int
	ErrorMessage string
}

type FindingRow struct {
	ScanID       string
	FindingID    string
	Type         string
	Severity     string
	Title        string
	HumanSummary string
	Path         []byte
	Evidence     []byte
	Remediation  string
	CreatedAt    time.Time
}

type ScanEventRow struct {
	ID        string
	ScanID    string
	Level     string
	Message   string
	Metadata  []byte
	CreatedAt time.Time
}

func (q *Queries) GetScan(ctx context.Context, scanID string) (ScanRow, error) {
	var row ScanRow
	err := q.db.QueryRowContext(
		ctx,
		`SELECT id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '')
		 FROM scans
		 WHERE id = $1`,
		scanID,
	).Scan(&row.ID, &row.Provider, &row.Status, &row.StartedAt, &row.FinishedAt, &row.AssetCount, &row.FindingCount, &row.ErrorMessage)
	if err != nil {
		return ScanRow{}, err
	}
	return row, nil
}

func (q *Queries) ListScans(ctx context.Context, limit int) ([]ScanRow, error) {
	rows, err := q.db.QueryContext(
		ctx,
		`SELECT id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '')
		 FROM scans
		 ORDER BY started_at DESC
		 LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []ScanRow{}
	for rows.Next() {
		var row ScanRow
		if err := rows.Scan(&row.ID, &row.Provider, &row.Status, &row.StartedAt, &row.FinishedAt, &row.AssetCount, &row.FindingCount, &row.ErrorMessage); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (q *Queries) ListFindings(ctx context.Context, limit int) ([]FindingRow, error) {
	rows, err := q.db.QueryContext(
		ctx,
		`SELECT scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at
		 FROM findings
		 ORDER BY created_at DESC
		 LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanFindingRows(rows)
}

func (q *Queries) ListFindingsByScan(ctx context.Context, scanID string, limit int) ([]FindingRow, error) {
	rows, err := q.db.QueryContext(
		ctx,
		`SELECT scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at
		 FROM findings
		 WHERE scan_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`,
		scanID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanFindingRows(rows)
}

func (q *Queries) ListScanEvents(ctx context.Context, scanID string, limit int) ([]ScanEventRow, error) {
	rows, err := q.db.QueryContext(
		ctx,
		`SELECT id, scan_id, level, message, metadata, created_at
		 FROM scan_events
		 WHERE scan_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`,
		scanID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []ScanEventRow{}
	for rows.Next() {
		var row ScanEventRow
		if err := rows.Scan(&row.ID, &row.ScanID, &row.Level, &row.Message, &row.Metadata, &row.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func scanFindingRows(rows *sql.Rows) ([]FindingRow, error) {
	result := []FindingRow{}
	for rows.Next() {
		var row FindingRow
		if err := rows.Scan(
			&row.ScanID,
			&row.FindingID,
			&row.Type,
			&row.Severity,
			&row.Title,
			&row.HumanSummary,
			&row.Path,
			&row.Evidence,
			&row.Remediation,
			&row.CreatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding rows: %w", err)
	}
	return result, nil
}
