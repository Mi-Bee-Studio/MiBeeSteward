// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package routes

import (
	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/domain"
)

// registerNotificationRoutes registers notification channels,
// rules, and logs.
func registerNotificationRoutes(r chi.Router, notificationHandler *handler.NotificationHandler) {
	// Notification channel routes, CapNotificationManage (admin-only
	// capability). Channels carry webhook URLs / tokens, so even the masked
	// read stays admin-only.
	r.Route("/api/v1/notification/channels", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapNotificationManage))
		r.Post("/", notificationHandler.CreateChannel)
		r.Get("/", notificationHandler.ListChannels)
		r.Get("/{id}", notificationHandler.GetChannel)
		r.Put("/{id}", notificationHandler.UpdateChannel)
		r.Patch("/{id}", notificationHandler.SetChannelEnabled)
		r.Delete("/{id}", notificationHandler.DeleteChannel)
		r.Post("/{id}/test", notificationHandler.TestChannel)
	})

	// Notification rule routes, CapNotificationManage (rules are config, like
	// channels).
	r.Route("/api/v1/notification/rules", func(r chi.Router) {
		r.Use(middleware.RequireCapability(domain.CapNotificationManage))
		r.Post("/", notificationHandler.CreateRule)
		r.Get("/", notificationHandler.ListRules)
		r.Get("/{id}", notificationHandler.GetRule)
		r.Put("/{id}", notificationHandler.UpdateRule)
		r.Patch("/{id}", notificationHandler.SetRuleEnabled)
		r.Delete("/{id}", notificationHandler.DeleteRule)
	})

	// Notification log routes, every authenticated user sees the header bell
	// and has their own per-user read state, so logs + mark-as-read are
	// RequireAuth (NOT RequireAdmin). Channel CRUD above stays admin-only.
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/api/v1/notification/logs", notificationHandler.ListNotificationLogs)
		r.Post("/api/v1/notification/logs/read", notificationHandler.MarkAllNotificationLogsRead)
	})
}
