package service

import (
	"testing"

	"mibee-steward/internal/domain"

	"github.com/stretchr/testify/require"
)

// ---------- Domain Helpers ----------

func TestValidateDeviceType_Valid(t *testing.T) {
	require.Equal(t, "pc", domain.ValidateDeviceType("pc"))
	require.Equal(t, "embedded", domain.ValidateDeviceType("embedded"))
	require.Equal(t, "iot", domain.ValidateDeviceType("iot"))
	require.Equal(t, "other", domain.ValidateDeviceType("other"))
}

func TestValidateDeviceType_Invalid(t *testing.T) {
	require.Equal(t, "other", domain.ValidateDeviceType("unknown"))
	require.Equal(t, "other", domain.ValidateDeviceType(""))
	require.Equal(t, "other", domain.ValidateDeviceType("PC"))
}
