package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/repository"
	"mibee-steward/internal/service"
	"mibee-steward/internal/service/notification"
)

// NotificationHandler handles HTTP requests for notification channel, alert rule, and log endpoints.
type NotificationHandler struct {
	svc        *service.NotificationService
	dispatcher *notification.Dispatcher
	auditRepo  *repository.AuditRepository
}

// NewNotificationHandler creates a new NotificationHandler.
func NewNotificationHandler(svc *service.NotificationService, dispatcher *notification.Dispatcher, auditRepo *repository.AuditRepository) *NotificationHandler {
	return &NotificationHandler{
		svc:        svc,
		dispatcher: dispatcher,
		auditRepo:  auditRepo,
	}
}

// --- Channel Endpoints ---

// CreateChannel handles POST /api/v1/notification/channels
func (h *NotificationHandler) CreateChannel(w http.ResponseWriter, r *http.Request) {
	var req domain.CreateChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.svc.CreateChannel(r.Context(), req)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), repository.AuditLog{
			UserID:       &userID,
			Action:       "admin.notification.channel.create",
			ResourceType: "notification_channel",
			ResourceID:   strconv.FormatInt(resp.ID, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Created(w, h.maskChannelPassword(resp))
}

// ListChannels handles GET /api/v1/notification/channels
func (h *NotificationHandler) ListChannels(w http.ResponseWriter, r *http.Request) {
	channels, err := h.svc.ListChannels(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list notification channels")
		return
	}

	// Mask passwords in all channels
	for i := range channels {
		h.maskChannelPasswordInPlace(&channels[i])
	}

	Success(w, domain.ChannelListResponse{
		Channels: channels,
		Total:    len(channels),
	})
}

// GetChannel handles GET /api/v1/notification/channels/{id}
func (h *NotificationHandler) GetChannel(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	resp, err := h.svc.GetChannel(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrChannelNotFound) {
			Error(w, http.StatusNotFound, "notification channel not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get notification channel")
		return
	}

	Success(w, h.maskChannelPassword(resp))
}

// UpdateChannel handles PUT /api/v1/notification/channels/{id}
func (h *NotificationHandler) UpdateChannel(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	var req domain.UpdateChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.svc.UpdateChannel(r.Context(), id, req)
	if err != nil {
		if errors.Is(err, service.ErrChannelNotFound) {
			Error(w, http.StatusNotFound, "notification channel not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to update notification channel")
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), repository.AuditLog{
			UserID:       &userID,
			Action:       "admin.notification.channel.update",
			ResourceType: "notification_channel",
			ResourceID:   strconv.FormatInt(id, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Success(w, h.maskChannelPassword(resp))
}

// DeleteChannel handles DELETE /api/v1/notification/channels/{id}
func (h *NotificationHandler) DeleteChannel(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	err = h.svc.DeleteChannel(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to delete notification channel")
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), repository.AuditLog{
			UserID:       &userID,
			Action:       "admin.notification.channel.delete",
			ResourceType: "notification_channel",
			ResourceID:   strconv.FormatInt(id, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Success(w, map[string]string{"message": "notification channel deleted"})
}

// TestChannel handles POST /api/v1/notification/channels/{id}/test
func (h *NotificationHandler) TestChannel(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	ch, err := h.svc.GetChannel(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrChannelNotFound) {
			Error(w, http.StatusNotFound, "notification channel not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get notification channel")
		return
	}

	if !ch.Enabled {
		Error(w, http.StatusBadRequest, "notification channel is disabled")
		return
	}

	payload := notification.Payload{
		Subject:   "Test Notification",
		Body:      "This is a test notification from MiBee Steward",
		Recipient: "test",
	}

	h.dispatcher.Dispatch(r.Context(), domain.ChannelType(ch.Type), ch.Config, payload, nil, ch.ID)

	Success(w, map[string]string{"message": "test notification dispatched"})
}

// --- Alert Rule Endpoints ---

// CreateAlertRule handles POST /api/v1/alert-rules
func (h *NotificationHandler) CreateAlertRule(w http.ResponseWriter, r *http.Request) {
	var req domain.CreateAlertRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.svc.CreateAlertRule(r.Context(), req)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), repository.AuditLog{
			UserID:       &userID,
			Action:       "admin.notification.rule.create",
			ResourceType: "alert_rule",
			ResourceID:   strconv.FormatInt(resp.ID, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Created(w, resp)
}

// ListAlertRules handles GET /api/v1/alert-rules
func (h *NotificationHandler) ListAlertRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.svc.ListAlertRules(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list alert rules")
		return
	}

	Success(w, domain.AlertRuleListResponse{
		Rules: rules,
		Total: len(rules),
	})
}

// GetAlertRule handles GET /api/v1/alert-rules/{id}
func (h *NotificationHandler) GetAlertRule(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	resp, err := h.svc.GetAlertRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrAlertRuleNotFound) {
			Error(w, http.StatusNotFound, "alert rule not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get alert rule")
		return
	}

	Success(w, resp)
}

// UpdateAlertRule handles PUT /api/v1/alert-rules/{id}
func (h *NotificationHandler) UpdateAlertRule(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	var req domain.UpdateAlertRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.svc.UpdateAlertRule(r.Context(), id, req)
	if err != nil {
		if errors.Is(err, service.ErrAlertRuleNotFound) {
			Error(w, http.StatusNotFound, "alert rule not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to update alert rule")
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), repository.AuditLog{
			UserID:       &userID,
			Action:       "admin.notification.rule.update",
			ResourceType: "alert_rule",
			ResourceID:   strconv.FormatInt(id, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Success(w, resp)
}

// DeleteAlertRule handles DELETE /api/v1/alert-rules/{id}
func (h *NotificationHandler) DeleteAlertRule(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	err = h.svc.DeleteAlertRule(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to delete alert rule")
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), repository.AuditLog{
			UserID:       &userID,
			Action:       "admin.notification.rule.delete",
			ResourceType: "alert_rule",
			ResourceID:   strconv.FormatInt(id, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Success(w, map[string]string{"message": "alert rule deleted"})
}

// --- Notification Log Endpoints ---

// ListNotificationLogs handles GET /api/v1/notification/logs
func (h *NotificationHandler) ListNotificationLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)

	logs, total, err := h.svc.ListNotificationLogs(r.Context(), limit, offset)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list notification logs")
		return
	}

	Success(w, domain.NotificationLogListResponse{
		Logs:  logs,
		Total: int(total),
	})
}

// --- Helpers ---

// parseID extracts and validates the {id} path parameter.
func (h *NotificationHandler) parseID(w http.ResponseWriter, r *http.Request) (int64, error) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid ID")
		return 0, err
	}
	return id, nil
}

// maskChannelPassword masks the SMTP password field in email channel config.
func (h *NotificationHandler) maskChannelPassword(ch *domain.ChannelResponse) *domain.ChannelResponse {
	h.maskChannelPasswordInPlace(ch)
	return ch
}

// maskChannelPasswordInPlace masks the SMTP password in the channel config if type is email.
func (h *NotificationHandler) maskChannelPasswordInPlace(ch *domain.ChannelResponse) {
	if ch.Type == string(domain.ChannelTypeEmail) && len(ch.Config) > 0 {
		var config map[string]interface{}
		if json.Unmarshal(ch.Config, &config) == nil {
			if _, ok := config["password"]; ok {
				config["password"] = "*****"
			}
			if masked, err := json.Marshal(config); err == nil {
				ch.Config = json.RawMessage(masked)
			}
		}
	}
}
