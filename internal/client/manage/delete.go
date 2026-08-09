// Package manage is declared in doc.go.
// This file implements file deletion (TASK step 2, FR-020): calls
// DELETE /api/v1/file/{file_id} and surfaces assignments_marked,
// providers_notified, and providers_pending — FR-020's own pending-provider
// retry language means providers_pending > 0 is expected steady-state text,
// not an error. HTTP 409 FILE_ALREADY_DELETED is treated as an idempotent
// success on the client side: from the data owner's point of view, the file
// is already in the state they asked for.
//
// [REF: FR-020, OAS deleteFile, ADR-007, MVP §8.2 Phase 15.4
// Session 15.4.1]

package manage

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

type deleteFileResponse struct {
	FileID            uuid.UUID `json:"file_id"`
	AssignmentsMarked int       `json:"assignments_marked"`
	ProvidersNotified int       `json:"providers_notified"`
	ProvidersPending  int       `json:"providers_pending"`
	Status            string    `json:"status"`
}

// DeleteResult is this package's rendered form of a successful (or
// already-deleted, idempotent) deletion.
type DeleteResult struct {
	AssignmentsMarked int
	ProvidersNotified int
	ProvidersPending  int
	// AlreadyDeleted is true when the server reported FILE_ALREADY_DELETED
	// (HTTP 409) — the deletion is idempotently successful, but there is no
	// fresh assignments_marked/providers_notified/providers_pending count
	// to report (the file was already gone before this call).
	AlreadyDeleted bool
}

// DeleteFile calls DELETE /api/v1/file/{file_id}.
func (m *Manager) DeleteFile(ctx context.Context, fileID uuid.UUID) (DeleteResult, error) {
	var resp deleteFileResponse
	httpResp, rawBody, err := m.api.doJSON(ctx, http.MethodDelete, "/api/v1/file/"+fileID.String(), nil, &resp)
	if err != nil {
		return DeleteResult{}, fmt.Errorf("manage: DeleteFile: %w", err)
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		return DeleteResult{
			AssignmentsMarked: resp.AssignmentsMarked,
			ProvidersNotified: resp.ProvidersNotified,
			ProvidersPending:  resp.ProvidersPending,
		}, nil
	case http.StatusConflict:
		if apiErr := decodeAPIError(rawBody); apiErr != nil && apiErr.ErrorCode == "FILE_ALREADY_DELETED" {
			// Idempotent success — the file is, from the data owner's
			// point of view, already in the state they asked for.
			return DeleteResult{AlreadyDeleted: true}, nil
		}
		if apiErr := decodeAPIError(rawBody); apiErr != nil {
			return DeleteResult{}, fmt.Errorf("manage: DeleteFile: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return DeleteResult{}, fmt.Errorf("manage: DeleteFile: unexpected status %d", httpResp.StatusCode)
	default:
		if apiErr := decodeAPIError(rawBody); apiErr != nil {
			return DeleteResult{}, fmt.Errorf("manage: DeleteFile: unexpected status %d: %w", httpResp.StatusCode, apiErr)
		}
		return DeleteResult{}, fmt.Errorf("manage: DeleteFile: unexpected status %d", httpResp.StatusCode)
	}
}
