// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

package assistants

import "github.com/AnachronisticAdmin/anachron-agent-gateway/acp"

// PermissionRequestData exposes the stable correlation/choice fields of a
// permission data part. Additional redacted display fields may also be present.
type PermissionRequestData struct {
	Type      string                 `json:"type"`
	RequestID string                 `json:"requestId"`
	Options   []acp.PermissionOption `json:"options"`
}

// PermissionDecisionData is an explicit decision, never inferred from prose.
type PermissionDecisionData struct {
	Type      string `json:"type"`
	RequestID string `json:"requestId"`
	Outcome   string `json:"outcome"`
	OptionID  string `json:"optionId,omitempty"`
}
