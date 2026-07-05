package alert

import (
	"context"

	"mibee-steward/internal/db"
)

// RuleMatchResult describes the outcome of evaluating a single rule against an event.
type RuleMatchResult struct {
	Matched bool
	RuleID  int64
	Reason  string // human-readable explanation
}

// RuleStore abstracts DB queries needed by the alert engine.
type RuleStore interface {
	ListEnabledAlertRules(ctx context.Context) ([]db.AlertRule, error)
	GetChannelByID(ctx context.Context, id int64) (db.NotificationChannel, error)
	UpdateAlertRule(ctx context.Context, arg db.UpdateAlertRuleParams) (db.AlertRule, error)
}
