package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

const (
	defaultWorkers = 3
	channelBuffer  = 100
	maxRetries     = 3
	retryBaseDelay = 1 * time.Second
)

// Dispatcher manages async notification delivery via a worker pool.
// Jobs are dispatched non-blocking onto a buffered channel.
type Dispatcher struct {
	channel       chan dispatchJob
	db            LogCreator
	logger        *slog.Logger
	wg            sync.WaitGroup
	cancel        context.CancelFunc
	senderFactory SenderFactory
}

// dispatchJob represents a single notification to be delivered.
type dispatchJob struct {
	ctx       context.Context
	channel   domain.ChannelType
	config    json.RawMessage
	payload   Payload
	ruleID    *int64
	channelID int64
}

// LogCreator abstracts the DB create call for testability.
type LogCreator interface {
	CreateNotificationLog(ctx context.Context, arg db.CreateNotificationLogParams) (db.NotificationLog, error)
}

// SenderFactory creates a Sender for the given channel type and config.
type SenderFactory func(channelType domain.ChannelType, config json.RawMessage) (Sender, error)

func NewDispatcher(db LogCreator, logger *slog.Logger) *Dispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Dispatcher{
		channel: make(chan dispatchJob, channelBuffer),
		db:      db,
		logger:  logger,
	}
}

// WithSenderFactory allows overriding the sender factory (for testing).
func (d *Dispatcher) WithSenderFactory(factory SenderFactory) *Dispatcher {
	d.senderFactory = factory
	return d
}

// senderFactory is the default factory, can be overridden for tests.
func (d *Dispatcher) getSenderFactory() SenderFactory {
	if d.senderFactory != nil {
		return d.senderFactory
	}
	return defaultSenderFactory
}

// defaultSenderFactory creates a Sender for the given channel type and config.

func defaultSenderFactory(channelType domain.ChannelType, config json.RawMessage) (Sender, error) {
	switch channelType {
	case domain.ChannelTypeWebhook:
		return NewWebhookSenderFromConfig(config)
	case domain.ChannelTypeEmail:
		return NewSMTPSenderFromConfig(config)
	default:
		return nil, fmt.Errorf("unsupported channel type: %s", channelType)
	}
}

// Start launches the worker goroutines.
func (d *Dispatcher) Start(ctx context.Context) {
	ctx, d.cancel = context.WithCancel(ctx)

	for i := 0; i < defaultWorkers; i++ {
		d.wg.Add(1)
		go d.worker(ctx, i)
	}

	d.logger.Info("notification dispatcher started", "workers", defaultWorkers)
}

// Stop signals workers to stop and waits for completion.
func (d *Dispatcher) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
	d.wg.Wait()
}

// Dispatch sends a job to the worker pool. Non-blocking — returns immediately.
// If the channel is full, the job is dropped and logged.
func (d *Dispatcher) Dispatch(ctx context.Context, channelType domain.ChannelType, config json.RawMessage, payload Payload, ruleID *int64, channelID int64) {
	job := dispatchJob{
		ctx:       ctx,
		channel:   channelType,
		config:    config,
		payload:   payload,
		ruleID:    ruleID,
		channelID: channelID,
	}

	select {
	case d.channel <- job:
		d.logger.Debug("notification dispatched", "channel", channelType, "recipient", payload.Recipient)
	default:
		d.logger.Warn("notification dropped — channel full", "channel", channelType, "recipient", payload.Recipient)
		d.logResult(ctx, ruleID, channelID, "failed", payload, "dispatch queue full")
	}
}

func (d *Dispatcher) worker(ctx context.Context, _ int) {
	defer d.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-d.channel:
			if !ok {
				return
			}
			d.processJob(job)
		}
	}
}

func (d *Dispatcher) processJob(job dispatchJob) {
	sender, err := d.getSenderFactory()(job.channel, job.config)
	if err != nil {
		d.logger.Error("failed to create sender", "channel", job.channel, "error", err)
		d.logResult(job.ctx, job.ruleID, job.channelID, "failed", job.payload, err.Error())
		return
	}

	var lastResult SendResult
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := retryBaseDelay * time.Duration(1<<(attempt-1)) // 1s, 2s, 4s
			d.logger.Debug("notification retry", "attempt", attempt+1, "delay", delay, "channel", job.channel)

			select {
			case <-job.ctx.Done():
				d.logResult(job.ctx, job.ruleID, job.channelID, "failed", job.payload, "context cancelled during retry")
				return
			case <-time.After(delay):
			}
		}

		result := sendWithSender(job.ctx, sender, job.payload, job.config)
		lastResult = result

		if result.Success {
			d.logResult(job.ctx, job.ruleID, job.channelID, "sent", job.payload, "")
			return
		}

		// Don't retry permanent errors
		if !result.IsRetryable() {
			d.logger.Warn("permanent send failure, not retrying", "channel", job.channel, "error", result.Error)
			d.logResult(job.ctx, job.ruleID, job.channelID, "failed", job.payload, result.Error)
			return
		}
	}

	// All retries exhausted
	d.logger.Error("notification send failed after all retries", "channel", job.channel, "error", lastResult.Error)
	d.logResult(job.ctx, job.ruleID, job.channelID, "failed", job.payload, lastResult.Error)
}

// sendWithSender calls the appropriate send method based on channel type.
func sendWithSender(ctx context.Context, sender Sender, payload Payload, config json.RawMessage) SendResult {
	// If sender is a WebhookSender, use SendWithConfig for the config-aware path
	if ws, ok := sender.(*WebhookSender); ok {
		return ws.SendWithConfig(ctx, payload, config)
	}
	return sender.Send(ctx, payload)
}

func (d *Dispatcher) logResult(ctx context.Context, ruleID *int64, channelID int64, status string, payload Payload, errMsg string) {
	payloadJSON, _ := json.Marshal(payload)

	_, err := d.db.CreateNotificationLog(ctx, db.CreateNotificationLogParams{
		RuleID:       ruleID,
		ChannelID:    &channelID,
		Status:       status,
		Payload:      string(payloadJSON),
		ErrorMessage: errMsg,
	})
	if err != nil {
		d.logger.Error("failed to log notification result", "status", status, "error", err)
	}
}
