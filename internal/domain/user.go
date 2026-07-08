package domain

import "time"

// UserRole represents a user's role in the system.
type UserRole string

const (
	RoleAdmin UserRole = "admin"
	RoleUser  UserRole = "user"
)

// Request types

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role,omitempty"` // optional, defaults to "user"
}

type LoginRequest struct {
	Username string `json:"username"` // accepts username or email
	Password string `json:"password"`
}

type UpdateProfileRequest struct {
	Email string `json:"email"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// Response types

type UserResponse struct {
	ID                 int64     `json:"id"`
	Username           string    `json:"username"`
	Email              string    `json:"email"`
	Role               string    `json:"role"`
	MustChangePassword bool      `json:"must_change_password"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type LoginResponse struct {
	Token             string       `json:"token"`
	User              UserResponse `json:"user"`
	TwoFactorRequired bool         `json:"two_factor_required,omitempty"`
}

type ListUsersResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total"`
}

// Context key type for user info.
type contextKey string

const (
	ContextKeyUserID contextKey = "user_id"
	ContextKeyRole   contextKey = "role"
	// ContextKeyAgentID / ContextKeyAgentNetworkID are set by the agent-token
	// middleware (RequireAgentToken) for machine-to-machine ingestion requests.
	// Distinct from the user JWT keys so a request is either a user session OR
	// an agent, never both.
	ContextKeyAgentID       contextKey = "agent_id"
	ContextKeyAgentNetworkID contextKey = "agent_network_id"
)
