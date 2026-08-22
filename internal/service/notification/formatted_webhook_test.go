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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
)

func testPayload() Payload {
	return Payload{Subject: "Device Lost: cam-01", Body: "Device: cam-01\nIP: 192.168.63.133"}
}

func TestFeishuSender_PayloadAndSignature(t *testing.T) {
	var gotBody map[string]any
	var gotSign, gotTS string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSign = r.Header.Get("X-Lark-Request-Signature")
		gotTS = r.Header.Get("X-Lark-Request-Timestamp")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"code":0,"msg":"success"}`))
	}))
	defer srv.Close()

	cfg, _ := json.Marshal(FeishuConfig{URL: srv.URL, Secret: "s3cret"})
	s := NewFormattedWebhookSender(domain.ChannelTypeFeishu)
	res := s.SendWithConfig(context.Background(), testPayload(), cfg)
	require.True(t, res.Success, "error: %s", res.Error)

	// payload shape: msg_type=text + content.text = subject + "\n" + body
	require.Equal(t, "text", gotBody["msg_type"])
	content := gotBody["content"].(map[string]any)
	require.Equal(t, "Device Lost: cam-01\nDevice: cam-01\nIP: 192.168.63.133", content["text"])

	// signature verifiable with the documented algorithm
	wantSign := base64.StdEncoding.EncodeToString(
		hmac.New(sha256.New, []byte(gotTS+"\n"+"s3cret")).Sum(nil))
	require.Equal(t, wantSign, gotSign)
}

func TestFeishuSender_BodyLevelErrorIsPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":19021,"msg":"sign match fail"}`)) // HTTP 200!
	}))
	defer srv.Close()

	cfg, _ := json.Marshal(FeishuConfig{URL: srv.URL})
	res := NewFormattedWebhookSender(domain.ChannelTypeFeishu).
		SendWithConfig(context.Background(), testPayload(), cfg)
	require.False(t, res.Success)
	require.Contains(t, res.Error, "sign match fail")
	require.False(t, res.IsRetryable(), "platform rejection must not retry")
}

func TestWeComSender(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()

	cfg, _ := json.Marshal(WeComConfig{URL: srv.URL})
	res := NewFormattedWebhookSender(domain.ChannelTypeWeCom).
		SendWithConfig(context.Background(), testPayload(), cfg)
	require.True(t, res.Success, "error: %s", res.Error)
	require.Equal(t, "text", gotBody["msgtype"])
	require.Equal(t, "Device Lost: cam-01\nDevice: cam-01\nIP: 192.168.63.133",
		gotBody["text"].(map[string]any)["content"])
}

func TestWeComSender_ErrcodeIsPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"errcode":95001,"errmsg":"invalid webhook url"}`))
	}))
	defer srv.Close()

	cfg, _ := json.Marshal(WeComConfig{URL: srv.URL})
	res := NewFormattedWebhookSender(domain.ChannelTypeWeCom).
		SendWithConfig(context.Background(), testPayload(), cfg)
	require.False(t, res.Success)
	require.Contains(t, res.Error, "invalid webhook url")
	require.False(t, res.IsRetryable())
}

func TestTelegramSender(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	defer srv.Close()

	// point the sender at the local test server instead of api.telegram.org
	orig := telegramBaseURL
	telegramBaseURL = srv.URL + "/bot"
	defer func() { telegramBaseURL = orig }()

	cfg, _ := json.Marshal(TelegramConfig{BotToken: "123:ABC", ChatID: "-100200"})
	res := NewFormattedWebhookSender(domain.ChannelTypeTelegram).
		SendWithConfig(context.Background(), testPayload(), cfg)
	require.True(t, res.Success, "error: %s", res.Error)
	require.Equal(t, "/bot123:ABC/sendMessage", gotPath)
	require.Equal(t, "-100200", gotBody["chat_id"])
	require.Contains(t, gotBody["text"], "Device Lost: cam-01")
}

func TestTelegramSender_NotOkIsPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`))
	}))
	defer srv.Close()

	orig := telegramBaseURL
	telegramBaseURL = srv.URL + "/bot"
	defer func() { telegramBaseURL = orig }()

	cfg, _ := json.Marshal(TelegramConfig{BotToken: "t", ChatID: "c"})
	res := NewFormattedWebhookSender(domain.ChannelTypeTelegram).
		SendWithConfig(context.Background(), testPayload(), cfg)
	require.False(t, res.Success)
	require.Contains(t, res.Error, "blocked by the user")
	require.False(t, res.IsRetryable())
}

func TestDiscordSender_TruncatesTo2000(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	long := Payload{Subject: "s", Body: strings.Repeat("x", 3000)}
	cfg, _ := json.Marshal(DiscordConfig{URL: srv.URL, Username: "MiBee"})
	res := NewFormattedWebhookSender(domain.ChannelTypeDiscord).
		SendWithConfig(context.Background(), long, cfg)
	require.True(t, res.Success, "error: %s", res.Error)
	require.Equal(t, "MiBee", gotBody["username"])
	require.LessOrEqual(t, len([]rune(gotBody["content"].(string))), 2000)
}

func TestFormattedWebhook_MissingConfigFieldsArePermanent(t *testing.T) {
	cases := []struct {
		kind   domain.ChannelType
		config string
	}{
		{domain.ChannelTypeFeishu, `{}`},
		{domain.ChannelTypeWeCom, `{}`},
		{domain.ChannelTypeTelegram, `{"bot_token":"t"}`},
		{domain.ChannelTypeDiscord, `{}`},
	}
	for _, tc := range cases {
		res := NewFormattedWebhookSender(tc.kind).
			SendWithConfig(context.Background(), testPayload(), json.RawMessage(tc.config))
		require.False(t, res.Success, "%s should fail on missing config", tc.kind)
		require.False(t, res.IsRetryable(), "%s config error must not retry", tc.kind)
	}
}

func TestDefaultSenderFactory_SupportsAllChannelTypes(t *testing.T) {
	// email validates its config at factory time (host+from required), unlike
	// the webhook-family senders which defer config parsing to send time.
	emailCfg, _ := json.Marshal(map[string]string{"host": "smtp.example.com", "from": "mibee@example.com"})
	configs := map[domain.ChannelType]json.RawMessage{
		domain.ChannelTypeEmail: emailCfg,
	}
	for _, ct := range []domain.ChannelType{
		domain.ChannelTypeWebhook, domain.ChannelTypeEmail,
		domain.ChannelTypeFeishu, domain.ChannelTypeWeCom,
		domain.ChannelTypeTelegram, domain.ChannelTypeDiscord,
	} {
		cfg, ok := configs[ct]
		if !ok {
			cfg = json.RawMessage(`{}`)
		}
		sender, err := defaultSenderFactory(ct, cfg)
		require.NoError(t, err, ct)
		require.NotNil(t, sender, ct)
	}
	_, err := defaultSenderFactory("carrier-pigeon", json.RawMessage(`{}`))
	require.Error(t, err)
}
