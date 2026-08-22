// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"mibee-steward/internal/domain"
)

// FormattedWebhookSender delivers notifications through third-party IM bot
// webhooks — Feishu/Lark, WeCom (企业微信群机器人), Telegram, Discord. All four
// are "formatted webhooks" at heart: POST a platform-specific JSON body to a
// bot endpoint, with per-platform auth (Feishu HMAC signature header,
// Telegram bot token embedded in the URL path). The generic `webhook`
// channel stays the raw-JSON escape hatch for everything else; these four
// exist so operators don't need an adapter lambda for the common chat
// platforms (#284).
//
// All platforms signal failures INSIDE a 2xx body (errcode/code/ok fields),
// so success requires both an HTTP 2xx and the platform's own status — and
// those body-level errors are marked Permanent (no retry burns).
type FormattedWebhookSender struct {
	Kind   domain.ChannelType
	Client *http.Client
}

// NewFormattedWebhookSender builds a sender for one of the four supported
// IM platforms. kind validity is enforced by domain.IsValidChannelType at
// channel-CRUD time; an unknown kind fails every send permanently.
func NewFormattedWebhookSender(kind domain.ChannelType) *FormattedWebhookSender {
	return &FormattedWebhookSender{
		Kind:   kind,
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

// FeishuConfig is the channel config for a 飞书/Lark custom bot. Secret is
// the bot's "签名校验" key — when set, every request carries
// X-Lark-Request-Timestamp + X-Lark-Request-Signature (HMAC-SHA256).
type FeishuConfig struct {
	URL    string `json:"url"`
	Secret string `json:"secret,omitempty"`
}

// WeComConfig is the channel config for a 企业微信群机器人 (group bot webhook).
type WeComConfig struct {
	URL string `json:"url"`
}

// TelegramConfig is the channel config for a Telegram Bot API chat.
type TelegramConfig struct {
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

// DiscordConfig is the channel config for a Discord incoming webhook.
type DiscordConfig struct {
	URL      string `json:"url"`
	Username string `json:"username,omitempty"`
}

// Send is not used — the dispatcher routes through SendWithConfig (the
// channel config blob is only known per-dispatch). Mirrors WebhookSender.
func (s *FormattedWebhookSender) Send(context.Context, Payload) SendResult {
	return SendResult{Success: false, Error: "use SendWithConfig instead", Permanent: true}
}

// SendWithConfig delivers payload to the platform configured for s.Kind.
func (s *FormattedWebhookSender) SendWithConfig(ctx context.Context, payload Payload, config json.RawMessage) SendResult {
	// IM bots render one flat text block: subject heading + detail body.
	text := payload.Subject + "\n" + payload.Body
	switch s.Kind {
	case domain.ChannelTypeFeishu:
		return s.sendFeishu(ctx, text, config)
	case domain.ChannelTypeWeCom:
		return s.sendWeCom(ctx, text, config)
	case domain.ChannelTypeTelegram:
		return s.sendTelegram(ctx, text, config)
	case domain.ChannelTypeDiscord:
		return s.sendDiscord(ctx, text, config)
	default:
		return SendResult{Success: false, Error: fmt.Sprintf("unsupported formatted-webhook kind: %s", s.Kind), Permanent: true}
	}
}

func (s *FormattedWebhookSender) sendFeishu(ctx context.Context, text string, config json.RawMessage) SendResult {
	var cfg FeishuConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return configError(err)
	}
	if cfg.URL == "" {
		return configError(fmt.Errorf("feishu webhook url is required"))
	}
	body := map[string]any{
		"msg_type": "text",
		"content":  map[string]string{"text": text},
	}
	headers := map[string]string{}
	if cfg.Secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		headers["X-Lark-Request-Timestamp"] = ts
		headers["X-Lark-Request-Signature"] = feishuSign(ts, cfg.Secret)
	}
	resp, respBody, err := s.postJSON(ctx, cfg.URL, body, headers)
	if err != nil {
		return SendResult{Success: false, Error: err.Error()}
	}
	// Feishu open-platform replies {"code":0,"msg":"success"} on success; some
	// older gateway variants use StatusCode/StatusMessage instead.
	var fr struct {
		Code          int    `json:"code"`
		Msg           string `json:"msg"`
		StatusCode    int    `json:"StatusCode"`
		StatusMessage string `json:"StatusMessage"`
	}
	_ = json.Unmarshal(respBody, &fr)
	if is2xx(resp.StatusCode) && fr.Code == 0 && fr.StatusCode == 0 {
		slog.Info("feishu notification sent", "status", resp.StatusCode)
		return SendResult{Success: true}
	}
	msg := platformError("feishu", resp.StatusCode, respBody, firstNonEmpty(fr.Msg, fr.StatusMessage))
	return SendResult{Success: false, Error: msg, Permanent: true}
}

func (s *FormattedWebhookSender) sendWeCom(ctx context.Context, text string, config json.RawMessage) SendResult {
	var cfg WeComConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return configError(err)
	}
	if cfg.URL == "" {
		return configError(fmt.Errorf("wecom webhook url is required"))
	}
	body := map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": text},
	}
	resp, respBody, err := s.postJSON(ctx, cfg.URL, body, nil)
	if err != nil {
		return SendResult{Success: false, Error: err.Error()}
	}
	var wr struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	_ = json.Unmarshal(respBody, &wr)
	if is2xx(resp.StatusCode) && wr.ErrCode == 0 {
		slog.Info("wecom notification sent", "status", resp.StatusCode)
		return SendResult{Success: true}
	}
	msg := platformError("wecom", resp.StatusCode, respBody, wr.ErrMsg)
	return SendResult{Success: false, Error: msg, Permanent: true}
}

// telegramBaseURL is the Bot API base (token appended by the sender).
// Package var so tests can point it at a local httptest server.
var telegramBaseURL = "https://api.telegram.org/bot"

func (s *FormattedWebhookSender) sendTelegram(ctx context.Context, text string, config json.RawMessage) SendResult {
	var cfg TelegramConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return configError(err)
	}
	if cfg.BotToken == "" || cfg.ChatID == "" {
		return configError(fmt.Errorf("telegram bot_token and chat_id are required"))
	}
	url := telegramBaseURL + cfg.BotToken + "/sendMessage"
	body := map[string]any{
		"chat_id": cfg.ChatID,
		"text":    text,
	}
	resp, respBody, err := s.postJSON(ctx, url, body, nil)
	if err != nil {
		return SendResult{Success: false, Error: err.Error()}
	}
	var tr struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(respBody, &tr)
	if is2xx(resp.StatusCode) && tr.OK {
		slog.Info("telegram notification sent", "status", resp.StatusCode)
		return SendResult{Success: true}
	}
	msg := platformError("telegram", resp.StatusCode, respBody, tr.Description)
	return SendResult{Success: false, Error: msg, Permanent: true}
}

func (s *FormattedWebhookSender) sendDiscord(ctx context.Context, text string, config json.RawMessage) SendResult {
	var cfg DiscordConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return configError(err)
	}
	if cfg.URL == "" {
		return configError(fmt.Errorf("discord webhook url is required"))
	}
	body := map[string]any{
		"content": truncateRunes(text, 2000), // Discord hard limit per message
	}
	if cfg.Username != "" {
		body["username"] = cfg.Username
	}
	resp, respBody, err := s.postJSON(ctx, cfg.URL, body, nil)
	if err != nil {
		return SendResult{Success: false, Error: err.Error()}
	}
	if is2xx(resp.StatusCode) { // 204 No Content is the normal success
		slog.Info("discord notification sent", "status", resp.StatusCode)
		return SendResult{Success: true}
	}
	return SendResult{Success: false, Error: platformError("discord", resp.StatusCode, respBody, ""), Permanent: true}
}

// postJSON marshals body, POSTs it with the extra headers, and returns the
// response plus its (read, closed) body. A non-2xx is NOT an error here —
// platform status handling is the caller's job.
func (s *FormattedWebhookSender) postJSON(ctx context.Context, url string, body any, headers map[string]string) (*http.Response, []byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	return resp, respBody, nil
}

// feishuSign computes the custom-bot signature: HMAC-SHA256 keyed by
// "<timestamp>\n<secret>" over an empty message, base64-encoded.
func feishuSign(timestamp, secret string) string {
	stringToSign := timestamp + "\n" + secret
	mac := hmac.New(sha256.New, []byte(stringToSign))
	mac.Write(nil) // empty payload per Feishu spec
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func is2xx(code int) bool { return code >= 200 && code < 300 }

func configError(err error) SendResult {
	return SendResult{Success: false, Error: fmt.Sprintf("invalid channel config: %v", err), Permanent: true}
}

func platformError(platform string, status int, body []byte, platformMsg string) string {
	msg := firstNonEmpty(platformMsg, string(body))
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return fmt.Sprintf("%s rejected the notification (status %d): %s", platform, status, msg)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncateRunes(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes])
}
