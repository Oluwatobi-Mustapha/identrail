package sqlcdb

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestQueriesGetScan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	q := New(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "coalesce"}).
		AddRow("scan-1", "aws", "completed", now, now, 2, 1, "")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '')
		 FROM scans
		 WHERE id = $1`)).WithArgs("scan-1").WillReturnRows(rows)

	scan, err := q.GetScan(context.Background(), "scan-1")
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if scan.ID != "scan-1" {
		t.Fatalf("unexpected scan id %q", scan.ID)
	}
}

func TestQueriesListFindingsByScan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	q := New(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow("scan-1", "f1", "ownerless_identity", "high", "Ownerless", "summary", []byte("[]"), []byte("{}"), "fix", now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at
		 FROM findings
		 WHERE scan_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`)).WithArgs("scan-1", 100).WillReturnRows(rows)

	result, err := q.ListFindingsByScan(context.Background(), "scan-1", 100)
	if err != nil {
		t.Fatalf("list findings by scan: %v", err)
	}
	if len(result) != 1 || result[0].FindingID != "f1" {
		t.Fatalf("unexpected results: %+v", result)
	}
}
