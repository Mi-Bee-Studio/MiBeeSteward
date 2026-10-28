// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

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
	// delayed-retry pacing (issue #633): after the in-process backoff ladder
	// (1s/2s/4s) is exhausted, a retryable failure requeues at these growing
	// delays until the bounded window expires. Covers the "receiver briefly
	// unreachable" outage (a restarted alert center, a network blip) without
	// any schema change — the delayed set is in-memory and dies with the
	// process (documented limitation).
)

// Delayed-retry pacing defaults (30s first backoff doubling to a 5m cap,
// swept every 15s). The per-instance pacing fields on Dispatcher let tests
// shrink the timeline race-free under -race.
const (
	retrySweepIntervalDefault = 15 * time.Second
	retryFirstDelayDefault    = 30 * time.Second
	retryMaxDelayDefault      = 5 * time.Minute
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

	// retryWindow bounds how long a retryable failure keeps requeueing
	// (notify.retry_window_minutes; 0 = give up after the fast ladder, the
	// historical behavior).
	retryWindow   time.Duration
	sweepInterval time.Duration
	firstDelay    time.Duration
	maxDelay      time.Duration

	delayedMu sync.Mutex
	delayed   map[*dispatchJob]time.Time // job → next requeue attempt
}

// dispatchJob represents a single notification to be delivered.
type dispatchJob struct {
	ctx       context.Context
	channel   domain.ChannelType
	config    json.RawMessage
	payload   Payload
	ruleID    *int64
	channelID int64

	// delayed-retry bookkeeping (firstAttempt is set on Dispatch)
	firstAttempt time.Time
	backoff      time.Duration // next delayed delay; 0 = not yet delayed
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
		channel:       make(chan dispatchJob, channelBuffer),
		db:            db,
		logger:        logger,
		delayed:       make(map[*dispatchJob]time.Time),
		sweepInterval: retrySweepIntervalDefault,
		firstDelay:    retryFirstDelayDefault,
		maxDelay:      retryMaxDelayDefault,
	}
}

// WithRetryWindow enables the bounded delayed-retry window (#633): retryable
// failures keep requeueing with growing backoff until the window since the
// first dispatch attempt expires. Must be called before Start.
func (d *Dispatcher) WithRetryWindow(window time.Duration) *Dispatcher {
	if window < 0 {
		window = 0
	}
	d.retryWindow = window
	return d
}

// withRetryPacing shrinks the delayed-retry timeline (tests only): first
// backoff, sweep interval and backoff cap. Must be called before Start.
func (d *Dispatcher) withRetryPacing(first, sweep, maxDelay time.Duration) *Dispatcher {
	if first > 0 {
		d.firstDelay = first
	}
	if sweep > 0 {
		d.sweepInterval = sweep
	}
	if maxDelay > 0 {
		d.maxDelay = maxDelay
	}
	return d
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
	case domain.ChannelTypeFeishu, domain.ChannelTypeWeCom,
		domain.ChannelTypeTelegram, domain.ChannelTypeDiscord:
		return NewFormattedWebhookSender(channelType), nil
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
	if d.retryWindow > 0 {
		d.wg.Add(1)
		go d.retrySweeper(ctx)
	}

	d.logger.Info("notification dispatcher started", "workers", defaultWorkers,
		"retry_window", d.retryWindow)
}

// Stop signals workers to stop and waits for completion. The delayed-retry
// set is dropped with the process (documented: a window does not survive a
// restart).
func (d *Dispatcher) Stop() {
	d.cancel()
	d.wg.Wait()
}

// retrySweeper periodically moves due delayed jobs back onto the dispatch
// channel; jobs whose bounded window expired get their final failed row.
func (d *Dispatcher) retrySweeper(ctx context.Context) {
	defer d.wg.Done()
	ticker := time.NewTicker(d.sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			var due []dispatchJob
			d.delayedMu.Lock()
			for job, at := range d.delayed {
				if now.Before(at) {
					continue
				}
				if now.Sub(job.firstAttempt) >= d.retryWindow {
					delete(d.delayed, job)
					d.logResult(ctx, job.ruleID, job.channelID, "failed", job.payload,
						"receiver unreachable: retry window expired")
					continue
				}
				delete(d.delayed, job)
				due = append(due, *job)
			}
			d.delayedMu.Unlock()
			for _, job := range due {
				parked := job
				select {
				case d.channel <- job:
				default:
					// channel full: park it for the next sweep instead of
					// dropping — the window still bounds total effort.
					d.delayedMu.Lock()
					d.delayed[&parked] = now.Add(d.sweepInterval)
					d.delayedMu.Unlock()
				}
			}
		}
	}
}

// Dispatch sends a job to the worker pool. Non-blocking, returns immediately.
// If the channel is full, the job is dropped and logged.
func (d *Dispatcher) Dispatch(ctx context.Context, channelType domain.ChannelType, config json.RawMessage, payload Payload, ruleID *int64, channelID int64) {
	job := dispatchJob{
		ctx:          ctx,
		channel:      channelType,
		config:       config,
		payload:      payload,
		ruleID:       ruleID,
		channelID:    channelID,
		firstAttempt: time.Now(),
	}

	select {
	case d.channel <- job:
		d.logger.Debug("notification dispatched", "channel", channelType, "recipient", payload.Recipient)
	default:
		d.logger.Warn("notification dropped: channel full", "channel", channelType, "recipient", payload.Recipient)
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

	// Fast ladder exhausted. A retryable failure inside an active window
	// (#633) parks the job for a later delayed attempt instead of giving up —
	// the sweeper requeues it (or writes the final failed row when the
	// window expires).
	if d.retryWindow > 0 && lastResult.IsRetryable() &&
		time.Since(job.firstAttempt) < d.retryWindow {
		if job.backoff == 0 {
			job.backoff = d.firstDelay
		} else if job.backoff < d.maxDelay {
			job.backoff *= 2
			if job.backoff > d.maxDelay {
				job.backoff = d.maxDelay
			}
		}
		d.delayedMu.Lock()
		d.delayed[&job] = time.Now().Add(job.backoff)
		d.delayedMu.Unlock()
		d.logger.Warn("notification parked for delayed retry",
			"channel", job.channel, "backoff", job.backoff,
			"window_left", d.retryWindow-time.Since(job.firstAttempt))
		return
	}

	// All retries exhausted
	d.logger.Error("notification send failed after all retries", "channel", job.channel, "error", lastResult.Error)
	d.logResult(job.ctx, job.ruleID, job.channelID, "failed", job.payload, lastResult.Error)
}

// sendWithSender calls the appropriate send method based on channel type.
// Senders whose delivery parameters live in the channel config blob
// (webhook URL, bot token, …) implement ConfigSender and get the raw config;
// everyone else (SMTP) was fully constructed from config at factory time.
func sendWithSender(ctx context.Context, sender Sender, payload Payload, config json.RawMessage) SendResult {
	if cs, ok := sender.(ConfigSender); ok {
		return cs.SendWithConfig(ctx, payload, config)
	}
	return sender.Send(ctx, payload)
}

// ConfigSender is implemented by senders that need the channel's raw JSON
// config at send time (per-dispatch URL/secret/token parsing).
type ConfigSender interface {
	SendWithConfig(ctx context.Context, payload Payload, config json.RawMessage) SendResult
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
