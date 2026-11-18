package repository

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/ory/fosite"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// firestoreRepository stores every record as one document in a single collection,
// mirroring the key layout of kvsRepository ("<kind>-<id>"). Each document holds:
//
//	kind       record type, e.g. "refresh_token"; used to scope revocation queries
//	request_id fosite request ID for request-backed records; used by revocation
//	data       the JSON-encoded record, identical to what the other backends store
//
// It suits serverless deployments (e.g. Cloud Run scaled to zero) where local files
// do not survive an instance restart.
type firestoreRepository struct {
	client     *firestore.Client
	collection *firestore.CollectionRef
}

type firestoreRecord struct {
	Kind      string `firestore:"kind"`
	RequestID string `firestore:"request_id,omitempty"`
	Data      []byte `firestore:"data"`
}

const (
	kindAuthorizeCode    = "authorize_code"
	kindAccessToken      = "access_token"
	kindRefreshToken     = "refresh_token"
	kindPKCERequest      = "pkce_request"
	kindClient           = "client"
	kindAuthorizeRequest = "authorize_request"
)

// ParseFirestoreDSN parses "projects/<project>/databases/<database>[/collections/<collection>]".
// An empty DSN means: project detected from the environment (ADC / metadata server),
// the "(default)" database, and the given default collection.
func ParseFirestoreDSN(dsn, defaultCollection string) (project, database, collection string, err error) {
	project, database, collection = firestore.DetectProjectID, firestore.DefaultDatabaseID, defaultCollection
	if dsn == "" {
		return project, database, collection, nil
	}
	parts := strings.Split(strings.Trim(dsn, "/"), "/")
	if (len(parts) != 4 && len(parts) != 6) || parts[0] != "projects" || parts[2] != "databases" ||
		(len(parts) == 6 && parts[4] != "collections") {
		return "", "", "", fmt.Errorf("invalid firestore DSN %q: want projects/<project>/databases/<database>[/collections/<collection>]", dsn)
	}
	project, database = parts[1], parts[3]
	if len(parts) == 6 {
		collection = parts[5]
	}
	if project == "" || database == "" || collection == "" {
		return "", "", "", fmt.Errorf("invalid firestore DSN %q: empty path segment", dsn)
	}
	return project, database, collection, nil
}

// NewFirestoreRepository connects to Cloud Firestore (Native mode). It honours
// FIRESTORE_EMULATOR_HOST, which the tests use.
func NewFirestoreRepository(ctx context.Context, projectID, databaseID, collection string) (Repository, error) {
	client, err := firestore.NewClientWithDatabase(ctx, projectID, databaseID)
	if err != nil {
		return nil, fmt.Errorf("failed to create firestore client: %w", err)
	}
	return &firestoreRepository{
		client:     client,
		collection: client.Collection(collection),
	}, nil
}

// docID builds a document ID that is always valid in Firestore: IDs must not contain
// "/" or be "." / "..", so the variable part is base64url-encoded.
func (r *firestoreRepository) doc(kind, id string) *firestore.DocumentRef {
	return r.collection.Doc(kind + "-" + base64.RawURLEncoding.EncodeToString([]byte(id)))
}

func mapFirestoreErr(err error) error {
	if status.Code(err) == codes.NotFound {
		return fosite.ErrNotFound
	}
	return err
}

func (r *firestoreRepository) put(ctx context.Context, kind, id, requestID string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}
	_, err = r.doc(kind, id).Set(ctx, firestoreRecord{Kind: kind, RequestID: requestID, Data: data})
	return err
}

func decodeRecord(snap *firestore.DocumentSnapshot, value any) error {
	var rec firestoreRecord
	if err := snap.DataTo(&rec); err != nil {
		return fmt.Errorf("failed to decode firestore document: %w", err)
	}
	return json.Unmarshal(rec.Data, value)
}

func (r *firestoreRepository) get(ctx context.Context, kind, id string, value any) error {
	snap, err := r.doc(kind, id).Get(ctx)
	if err != nil {
		return mapFirestoreErr(err)
	}
	return decodeRecord(snap, value)
}

func (r *firestoreRepository) delete(ctx context.Context, kind, id string) error {
	// Deleting a missing document is not an error, matching bbolt's Delete.
	_, err := r.doc(kind, id).Delete(ctx)
	return err
}

func (r *firestoreRepository) putRequest(ctx context.Context, kind, id string, req fosite.Requester) error {
	return r.put(ctx, kind, id, req.GetID(), models.FromFositeReq(req))
}

func (r *firestoreRepository) getRequest(ctx context.Context, kind, id string, sess fosite.Session) (fosite.Requester, *models.Request, error) {
	var req models.Request
	if err := r.get(ctx, kind, id, &req); err != nil {
		return nil, nil, err
	}
	fositeReq := req.ToFositeReq()
	if err := restoreSession(fositeReq, req.SessionData, sess); err != nil {
		return nil, nil, err
	}
	return fositeReq, &req, nil
}

func (r *firestoreRepository) CreateAuthorizeCodeSession(ctx context.Context, code string, fositeReq fosite.Requester) error {
	return r.putRequest(ctx, kindAuthorizeCode, code, fositeReq)
}

func (r *firestoreRepository) GetAuthorizeCodeSession(ctx context.Context, code string, sess fosite.Session) (fosite.Requester, error) {
	fositeReq, _, err := r.getRequest(ctx, kindAuthorizeCode, code, sess)
	return fositeReq, err
}

func (r *firestoreRepository) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return r.delete(ctx, kindAuthorizeCode, code)
}

func (r *firestoreRepository) CreateAccessTokenSession(ctx context.Context, signature string, fositeReq fosite.Requester) error {
	return r.putRequest(ctx, kindAccessToken, signature, fositeReq)
}

func (r *firestoreRepository) GetAccessTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	fositeReq, _, err := r.getRequest(ctx, kindAccessToken, signature, sess)
	return fositeReq, err
}

func (r *firestoreRepository) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return r.delete(ctx, kindAccessToken, signature)
}

func (r *firestoreRepository) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, req fosite.Requester) error {
	return r.putRequest(ctx, kindRefreshToken, signature, req)
}

func (r *firestoreRepository) GetRefreshTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	fositeReq, req, err := r.getRequest(ctx, kindRefreshToken, signature, sess)
	if err != nil {
		return nil, err
	}
	if isRotatedBeyondGracePeriod(req.RotatedAt) {
		return fositeReq, fosite.ErrInactiveToken
	}
	return fositeReq, nil
}

func (r *firestoreRepository) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return r.delete(ctx, kindRefreshToken, signature)
}

// RotateRefreshToken marks the token as rotated once. The read-check-write runs in a
// transaction so two concurrent refreshes can't both record a fresh rotation time.
func (r *firestoreRepository) RotateRefreshToken(ctx context.Context, requestID string, signature string) error {
	ref := r.doc(kindRefreshToken, signature)
	return r.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		snap, err := tx.Get(ref)
		if err != nil {
			return mapFirestoreErr(err)
		}
		var rec firestoreRecord
		if err := snap.DataTo(&rec); err != nil {
			return fmt.Errorf("failed to decode firestore document: %w", err)
		}
		var req models.Request
		if err := json.Unmarshal(rec.Data, &req); err != nil {
			return err
		}
		if !req.RotatedAt.IsZero() {
			return nil
		}
		req.RotatedAt = time.Now().UTC()
		data, err := json.Marshal(req)
		if err != nil {
			return err
		}
		rec.Data = data
		return tx.Set(ref, rec)
	})
}

// RevokeRefreshToken revokes every refresh token of the grant (RFC 7009 section 2.1).
func (r *firestoreRepository) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return r.revokeSessions(ctx, kindRefreshToken, requestID)
}

// RevokeAccessToken revokes every access token of the grant (RFC 7009 section 2.1).
func (r *firestoreRepository) RevokeAccessToken(ctx context.Context, requestID string) error {
	return r.revokeSessions(ctx, kindAccessToken, requestID)
}

func (r *firestoreRepository) revokeSessions(ctx context.Context, kind, requestID string) error {
	query := r.collection.Where("kind", "==", kind).Where("request_id", "==", requestID)
	return r.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		snaps, err := tx.Documents(query).GetAll()
		if err != nil {
			return err
		}
		for _, snap := range snaps {
			if err := tx.Delete(snap.Ref); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *firestoreRepository) RegisterClient(ctx context.Context, fositeClient fosite.Client) error {
	return r.put(ctx, kindClient, fositeClient.GetID(), "", models.FromFositeClient(fositeClient))
}

func (r *firestoreRepository) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var client models.Client
	if err := r.get(ctx, kindClient, id, &client); err != nil {
		return nil, err
	}
	return client.ToFositeClient(), nil
}

func (r *firestoreRepository) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return errors.New("not implemented")
}

func (r *firestoreRepository) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return errors.New("not implemented")
}

func (r *firestoreRepository) CreatePKCERequestSession(ctx context.Context, signature string, req fosite.Requester) error {
	return r.putRequest(ctx, kindPKCERequest, signature, req)
}

func (r *firestoreRepository) GetPKCERequestSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	fositeReq, _, err := r.getRequest(ctx, kindPKCERequest, signature, sess)
	return fositeReq, err
}

func (r *firestoreRepository) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return r.delete(ctx, kindPKCERequest, signature)
}

func (r *firestoreRepository) CreateAuthorizeRequest(ctx context.Context, fositeAR fosite.AuthorizeRequester) error {
	return r.put(ctx, kindAuthorizeRequest, fositeAR.GetID(), fositeAR.GetID(), models.FromFositeAuthorizeRequest(fositeAR))
}

func (r *firestoreRepository) GetAuthorizeRequest(ctx context.Context, requestID string) (fosite.AuthorizeRequester, error) {
	var ar models.AuthorizeRequest
	if err := r.get(ctx, kindAuthorizeRequest, requestID, &ar); err != nil {
		return nil, err
	}
	return ar.ToFositeAuthorizeRequest(), nil
}

func (r *firestoreRepository) DeleteAuthorizeRequest(ctx context.Context, requestID string) error {
	return r.delete(ctx, kindAuthorizeRequest, requestID)
}

func (r *firestoreRepository) Close() error {
	return r.client.Close()
}
