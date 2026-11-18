package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
)

// newFirestoreTestRepository returns a repository backed by the Firestore emulator, using a
// collection unique to the test so tests don't see each other's documents. It skips the
// test when FIRESTORE_EMULATOR_HOST is not set, e.g.:
//
//	gcloud emulators firestore start --host-port=127.0.0.1:8085
//	FIRESTORE_EMULATOR_HOST=127.0.0.1:8085 go test ./pkg/repository/...
func newFirestoreTestRepository(t *testing.T) (Repository, error) {
	t.Helper()
	if os.Getenv("FIRESTORE_EMULATOR_HOST") == "" {
		t.Skip("FIRESTORE_EMULATOR_HOST not set; skipping Firestore backend test")
	}
	collection := fmt.Sprintf("%s-%d", strings.NewReplacer("/", "_").Replace(t.Name()), time.Now().UnixNano())
	return NewFirestoreRepository(context.Background(), "test-project", "(default)", collection)
}

func TestParseFirestoreDSN(t *testing.T) {
	tests := []struct {
		dsn                           string
		project, database, collection string
		wantErr                       bool
	}{
		{dsn: "", project: "*detect-project-id*", database: "(default)", collection: "def"},
		{dsn: "projects/p/databases/(default)", project: "p", database: "(default)", collection: "def"},
		{dsn: "projects/p/databases/db/collections/c", project: "p", database: "db", collection: "c"},
		{dsn: "/projects/p/databases/db/", project: "p", database: "db", collection: "def"},
		{dsn: "projects/p", wantErr: true},
		{dsn: "projects/p/databases/db/collections", wantErr: true},
		{dsn: "project/p/databases/db", wantErr: true},
		{dsn: "projects//databases/db", wantErr: true},
		{dsn: "projects/p/databases/db/tables/c", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.dsn, func(t *testing.T) {
			project, database, collection, err := ParseFirestoreDSN(tt.dsn, "def")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.dsn)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if project != tt.project || database != tt.database || collection != tt.collection {
				t.Fatalf("got (%q, %q, %q), want (%q, %q, %q)", project, database, collection, tt.project, tt.database, tt.collection)
			}
		})
	}
}

func TestFirestoreRepositoryRoundTrip(t *testing.T) {
	repo, err := newFirestoreTestRepository(t)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()

	// IDs containing "/" must still map to valid document IDs.
	client := &fosite.DefaultClient{
		ID:           "client/with/slashes",
		Secret:       []byte("secret"),
		RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	}
	if err := repo.RegisterClient(ctx, client); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	got, err := repo.GetClient(ctx, client.ID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.GetID() != client.ID || got.GetRedirectURIs()[0] != client.RedirectURIs[0] {
		t.Fatalf("client mismatch: %+v", got)
	}
	if _, err := repo.GetClient(ctx, "missing"); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing client, got %v", err)
	}

	req := &fosite.Request{
		ID:             "req-1",
		RequestedAt:    time.Now().UTC().Round(time.Second),
		Client:         client,
		RequestedScope: []string{"openid"},
		GrantedScope:   []string{"openid"},
		Session:        &fosite.DefaultSession{Subject: "user@example.com"},
	}
	if err := repo.CreateAuthorizeCodeSession(ctx, "code-1", req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}
	sess := &fosite.DefaultSession{}
	gotReq, err := repo.GetAuthorizeCodeSession(ctx, "code-1", sess)
	if err != nil {
		t.Fatalf("GetAuthorizeCodeSession: %v", err)
	}
	if gotReq.GetID() != req.ID || sess.Subject != "user@example.com" {
		t.Fatalf("authorize code session mismatch: id=%q subject=%q", gotReq.GetID(), sess.Subject)
	}
	if err := repo.InvalidateAuthorizeCodeSession(ctx, "code-1"); err != nil {
		t.Fatalf("InvalidateAuthorizeCodeSession: %v", err)
	}
	if _, err := repo.GetAuthorizeCodeSession(ctx, "code-1", &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after invalidation, got %v", err)
	}
	// Deleting something that doesn't exist is not an error (matches bbolt).
	if err := repo.DeletePKCERequestSession(ctx, "never-created"); err != nil {
		t.Fatalf("DeletePKCERequestSession on missing doc: %v", err)
	}
	if err := repo.RotateRefreshToken(ctx, "req-1", "never-created"); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("expected ErrNotFound rotating a missing refresh token, got %v", err)
	}
}

func TestFirestoreRepositoryRefreshTokenReuseDetection(t *testing.T) {
	originalGrace := RefreshTokenGracePeriod
	RefreshTokenGracePeriod = 200 * time.Millisecond
	defer func() { RefreshTokenGracePeriod = originalGrace }()

	repo, err := newFirestoreTestRepository(t)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()

	req := &fosite.Request{
		ID:          "req-rt",
		RequestedAt: time.Now().UTC().Round(time.Second),
		Client:      &fosite.DefaultClient{ID: "client-rt"},
		Session:     &fosite.DefaultSession{Subject: "test-user"},
	}
	if err := repo.CreateRefreshTokenSession(ctx, "sig-rt", "sig-at", req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}
	if err := repo.RotateRefreshToken(ctx, req.ID, "sig-rt"); err != nil {
		t.Fatalf("RotateRefreshToken: %v", err)
	}
	// A second rotation must not move the rotation time forward.
	if err := repo.RotateRefreshToken(ctx, req.ID, "sig-rt"); err != nil {
		t.Fatalf("second RotateRefreshToken: %v", err)
	}
	if _, err := repo.GetRefreshTokenSession(ctx, "sig-rt", &fosite.DefaultSession{}); err != nil {
		t.Fatalf("rotated token within grace period should be accepted: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if _, err := repo.GetRefreshTokenSession(ctx, "sig-rt", &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Fatalf("expected ErrInactiveToken beyond grace period, got %v", err)
	}
}
