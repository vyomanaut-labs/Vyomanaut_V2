// Tests for watch.go (M17-E Session 17.6.2).
//
// Tests:
//   - TestWatchJSONSnapshotShape
//   - TestWatchJSONSnapshotSurvivesPartialFetchFailure
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeAdminServer stands in for cmd/microservice, implementing the five
// endpoints the watch console's fan-out fetch calls. Each handler is
// swappable per test via the *Fn fields (nil means "200 with a minimal
// empty body").
type fakeAdminServer struct {
	readinessFn func(w http.ResponseWriter)
	providersFn func(w http.ResponseWriter)
}

func newFakeAdminServer(t *testing.T, cfg fakeAdminServer) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/readiness", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg.readinessFn != nil {
			cfg.readinessFn(w)
			return
		}
		_ = json.NewEncoder(w).Encode(readinessAdminResponse{Mode: "demo", AllConditionsMet: true})
	})
	mux.HandleFunc("/api/v1/admin/providers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg.providersFn != nil {
			cfg.providersFn(w)
			return
		}
		_ = json.NewEncoder(w).Encode(adminProvidersResponse{Total: 0})
	})
	mux.HandleFunc("/api/v1/admin/repair/queue", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(repairQueueAdminResponse{})
	})
	mux.HandleFunc("/api/v1/admin/audit/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(auditStatsAdminResponse{})
	})
	mux.HandleFunc("/api/v1/admin/vetting/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(vettingStatusAdminResponse{})
	})
	return httptest.NewServer(mux)
}

// TestWatchJSONSnapshotShape confirms `operator watch --json` performs
// exactly one fetch cycle, exits 0, and emits a watchSnapshot whose five
// endpoint fields are all populated — task item 5's own wording ("so
// 17.8.2 can assert on the console's own view").
func TestWatchJSONSnapshotShape(t *testing.T) {
	server := newFakeAdminServer(t, fakeAdminServer{})
	defer server.Close()

	var out, errOut bytes.Buffer
	code := dispatchWatch([]string{
		"--microservice-url=" + server.URL,
		"--admin-api-key=test-key",
		"--json",
	}, &out, &errOut)

	if code != 0 {
		t.Fatalf("dispatchWatch --json exit code = %d, want 0, stderr = %s", code, errOut.String())
	}

	var snap watchSnapshot
	if err := json.Unmarshal(out.Bytes(), &snap); err != nil {
		t.Fatalf("unmarshal --json output: %v\noutput was: %s", err, out.String())
	}
	if snap.Readiness == nil {
		t.Error("snapshot.readiness is nil, want populated")
	}
	if snap.Providers == nil {
		t.Error("snapshot.providers is nil, want populated")
	}
	if snap.RepairQueue == nil {
		t.Error("snapshot.repair_queue is nil, want populated")
	}
	if snap.AuditStats == nil {
		t.Error("snapshot.audit_stats is nil, want populated")
	}
	if snap.VettingStatus == nil {
		t.Error("snapshot.vetting_status is nil, want populated")
	}
	if len(snap.FetchErrors) != 0 {
		t.Errorf("snapshot.fetch_errors = %v, want empty (every endpoint succeeded)", snap.FetchErrors)
	}
}

// TestWatchJSONSnapshotSurvivesPartialFetchFailure confirms one endpoint
// returning an error still produces a snapshot with the other four
// endpoints populated and the failure recorded in fetch_errors, rather
// than the whole command failing.
func TestWatchJSONSnapshotSurvivesPartialFetchFailure(t *testing.T) {
	server := newFakeAdminServer(t, fakeAdminServer{
		readinessFn: func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error_code":"INTERNAL","message":"boom"}`))
		},
	})
	defer server.Close()

	var out, errOut bytes.Buffer
	code := dispatchWatch([]string{
		"--microservice-url=" + server.URL,
		"--admin-api-key=test-key",
		"--json",
	}, &out, &errOut)

	if code != 0 {
		t.Fatalf("dispatchWatch --json exit code = %d, want 0 (a partial failure still yields a snapshot), stderr = %s", code, errOut.String())
	}

	var snap watchSnapshot
	if err := json.Unmarshal(out.Bytes(), &snap); err != nil {
		t.Fatalf("unmarshal --json output: %v", err)
	}
	if snap.Readiness != nil {
		t.Error("snapshot.readiness populated despite the endpoint failing, want nil")
	}
	if snap.Providers == nil {
		t.Error("snapshot.providers is nil, want populated (that endpoint did not fail)")
	}
	if len(snap.FetchErrors) != 1 {
		t.Errorf("snapshot.fetch_errors = %v, want exactly 1 entry", snap.FetchErrors)
	}
}
