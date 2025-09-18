package main

import (
	"context"
	"encoding/json"
	
	"log"
	"net/http"
	"os"
	"time"
	"sync"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	
	"golang.org/x/crypto/bcrypt"

	"strings"
	"crypto/sha256"
	"fmt"
	"io"
	"mime/multipart"
	
	"github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/you/balkanid-auth/storage"
)

type UploadResponse struct {
	FileID   string `json:"file_id"`
	Filename string `json:"filename"`
	BlobID   string `json:"blob_id"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Mime     string `json:"mime"`
	Deduped  bool   `json:"deduped"`
}
type Server struct {
	pool      *pgxpool.Pool
	jwtSecret string
	minio     *storage.MinioClient
	rateLimits map[string]*RateLimiter
	mu         sync.Mutex
}

type SignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name,omitempty"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string `json:"token"`
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type RateLimiter struct {
    tokens      int
    lastRefill  time.Time
    maxTokens   int
    refillRate  time.Duration
	mu         sync.Mutex
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
        w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusNoContent)
            return
        }
        next(w, r)
    }
}
func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable required")
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable required")
	}
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("failed to connect to db: %v", err)
	}
	defer pool.Close()

	minioClient := storage.NewMinioClient()

	srv := &Server{
		pool:      pool,
		jwtSecret: jwtSecret,
		minio:     minioClient,
		rateLimits: make(map[string]*RateLimiter),
	}

	http.HandleFunc("/api/v1/signup", withCORS(srv.handleSignup))
	http.HandleFunc("/api/v1/login", withCORS(srv.handleLogin))

	http.HandleFunc("/api/v1/upload", withCORS(srv.withAuth(srv.withLimit(srv.handleUpload))))
	http.HandleFunc("/api/v1/files", withCORS(srv.withAuth(srv.withLimit(srv.handleListFiles))))	
	http.HandleFunc("/api/v1/delete/", withCORS(srv.withAuth(srv.withLimit(srv.handleDeleteFile))))
	http.HandleFunc("/api/v1/share/", withCORS(srv.withAuth(srv.withLimit(srv.handleShareFile))))
	http.HandleFunc("/api/v1/download/", withCORS(srv.withAuth(srv.withLimit(srv.handlePrivateDownload))))
	http.HandleFunc("/api/v1/savings", withCORS(srv.withAuth(srv.withLimit(srv.handleSavings))))


	http.HandleFunc("/api/v1/public/", withCORS(srv.handlePublicDownload))


	


	log.Printf("server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}



func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.Email = normalize(req.Email)
	if req.Email == "" || len(req.Password) < 6 {
		http.Error(w, "email and password(min 6) required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	
	var exists bool
	q := "SELECT EXISTS(SELECT 1 FROM users WHERE email=$1)"
	if err := s.pool.QueryRow(ctx, q, req.Email).Scan(&exists); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "email already registered", http.StatusConflict)
		return
	}

	
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "error hashing password", http.StatusInternalServerError)
		return
	}

	uid := uuid.New().String()
	insert := `INSERT INTO users (id, email, password_hash, name) VALUES ($1,$2,$3,$4)`
	_, err = s.pool.Exec(ctx, insert, uid, req.Email, string(hash), req.Name)
	if err != nil {
		http.Error(w, "db insert error", http.StatusInternalServerError)
		return
	}

	token, err := s.createJWT(uid, req.Email)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}

	resp := AuthResponse{
		Token: token,
		ID:    uid,
		Email: req.Email,
		Name:  req.Name,
	}
	writeJSON(w, resp, http.StatusCreated)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.Email = normalize(req.Email)
	if req.Email == "" || req.Password == "" {
		http.Error(w, "email and password required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	var id string
	var hash string
	var name *string
	q := `SELECT id, password_hash, name FROM users WHERE email=$1`
	row := s.pool.QueryRow(ctx, q, req.Email)
	if err := row.Scan(&id, &hash, &name); err != nil {
		
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := s.createJWT(id, req.Email)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}

	resp := AuthResponse{
		Token: token,
		ID:    id,
		Email: req.Email,
	}
	if name != nil {
		resp.Name = *name
	}
	writeJSON(w, resp, http.StatusOK)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    userID := getUserID(r)
    if userID == "" {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    ctx := r.Context()

    // Parse upload
    err := r.ParseMultipartForm(32 << 20) 
    if err != nil {
        http.Error(w, "invalid form", http.StatusBadRequest)
        return
    }

    // Check storage already used
    var used int64
    err = s.pool.QueryRow(ctx, "SELECT COALESCE(SUM(size),0) FROM files WHERE owner_id=$1", userID).Scan(&used)
    if err != nil {
        http.Error(w, "db error", http.StatusInternalServerError)
        return
    }

    var responses []UploadResponse

    // Validate and save each file
    for _, files := range r.MultipartForm.File {
        for _, fh := range files {
            // Quota check before saving
            if used+fh.Size > defaultQuota {
                http.Error(w, "storage quota exceeded (10 MB)", http.StatusForbidden)
                return
            }

            // Save file to DB + MinIO
            res, err := s.saveFile(userID, fh)
            if err != nil {
                http.Error(w, "upload error: "+err.Error(), http.StatusInternalServerError)
                return
            }

            responses = append(responses, res)
            used += fh.Size
        }
    }

    writeJSON(w, responses, http.StatusOK)
}

func (s *Server) saveFile(userID string, fh *multipart.FileHeader) (UploadResponse, error) {
	file, err := fh.Open()
	if err != nil {
		return UploadResponse{}, err
	}
	defer file.Close()

	// compute sha256 + size
	h := sha256.New()
	size, err := io.Copy(h, file)
	if err != nil {
		return UploadResponse{}, err
	}
	sha := fmt.Sprintf("%x", h.Sum(nil))

	// rewind file for upload
	file.Seek(0, io.SeekStart)

	// check if blob exists
	ctx := context.Background()
	var blobID string
	
	q := `SELECT id FROM blobs WHERE sha256=$1`
	err = s.pool.QueryRow(ctx, q, sha).Scan(&blobID)
	if err == nil {
		
		_, _ = s.pool.Exec(ctx, "UPDATE blobs SET ref_count = ref_count+1 WHERE id=$1", blobID)
		fileID := uuid.New().String()
		_, _ = s.pool.Exec(ctx, `INSERT INTO files (id, owner_id, blob_id, filename, mime, size) VALUES ($1,$2,$3,$4,$5,$6)`,
			fileID, userID, blobID, fh.Filename, fh.Header.Get("Content-Type"), size)
		return UploadResponse{FileID: fileID, Filename: fh.Filename, BlobID: blobID, SHA256: sha, Size: size, Mime: fh.Header.Get("Content-Type"), Deduped: true}, nil
	}

	
	blobID = uuid.New().String()
	storageKey := sha

	_, err = s.minio.Client.PutObject(ctx, s.minio.Bucket, storageKey, file, size, minio.PutObjectOptions{
		ContentType: fh.Header.Get("Content-Type"),
	})
	if err != nil {
		return UploadResponse{}, err
	}

	_, err = s.pool.Exec(ctx, `INSERT INTO blobs (id, sha256, size, mime, storage_key) VALUES ($1,$2,$3,$4,$5)`,
		blobID, sha, size, fh.Header.Get("Content-Type"), storageKey)
	if err != nil {
		return UploadResponse{}, err
	}

	fileID := uuid.New().String()
	_, err = s.pool.Exec(ctx, `INSERT INTO files (id, owner_id, blob_id, filename, mime, size) VALUES ($1,$2,$3,$4,$5,$6)`,
		fileID, userID, blobID, fh.Filename, fh.Header.Get("Content-Type"), size)
	if err != nil {
		return UploadResponse{}, err
	}

	return UploadResponse{FileID: fileID, Filename: fh.Filename, BlobID: blobID, SHA256: sha, Size: size, Mime: fh.Header.Get("Content-Type"), Deduped: false}, nil
}

func (s *Server) createJWT(userID, email string) (string, error) {
	
	claims := jwt.MapClaims{
		"sub":   userID,
		"email": email,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"iss":   "balkanid-auth",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", err
	}
	return signed, nil
}


func writeJSON(w http.ResponseWriter, v interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := getUserID(r)
	if userID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	rows, err := s.pool.Query(ctx, `
		SELECT f.id, f.filename, f.mime, f.size, f.created_at,
		       b.sha256, b.storage_key
		FROM files f
		JOIN blobs b ON f.blob_id = b.id
		WHERE f.owner_id=$1
		ORDER BY f.created_at DESC
	`, userID)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type FileMetadata struct {
		ID         string `json:"id"`
		Filename   string `json:"filename"`
		Mime       string `json:"mime"`
		Size       int64  `json:"size"`
		UploadedAt time.Time `json:"uploaded_at"`
		SHA256     string `json:"sha256"`
		StorageKey string `json:"storage_key"`
	}

	var files []FileMetadata
	for rows.Next() {
		var f FileMetadata
		if err := rows.Scan(&f.ID, &f.Filename, &f.Mime, &f.Size, &f.UploadedAt, &f.SHA256, &f.StorageKey); err != nil {
			http.Error(w, "scan error", http.StatusInternalServerError)
			return
		}
		files = append(files, f)
	}

	writeJSON(w, files, http.StatusOK)
}

func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := getUserID(r)
	if userID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract file ID from path
	fileID := strings.TrimPrefix(r.URL.Path, "/api/v1/delete/")
	if fileID == "" {
		http.Error(w, "file id required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1) Ensure file exists and belongs to this user, fetch blob info
	var blobID, storageKey string
	var refCount int
	query := `
		SELECT b.id, b.storage_key, b.ref_count
		FROM files f
		JOIN blobs b ON f.blob_id = b.id
		WHERE f.id=$1 AND f.owner_id=$2
		FOR UPDATE
	`
	if err := tx.QueryRow(ctx, query, fileID, userID).Scan(&blobID, &storageKey, &refCount); err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "file not found or not owned by user", http.StatusNotFound)
			return
		}
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// 2) Delete file row
	if _, err := tx.Exec(ctx, `DELETE FROM files WHERE id=$1`, fileID); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// 3) Update or delete blob row
	if refCount > 1 {
		if _, err := tx.Exec(ctx, `UPDATE blobs SET ref_count = ref_count - 1 WHERE id=$1`, blobID); err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			http.Error(w, "db commit error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"status": "deleted", "deduped": true}, http.StatusOK)
		return
	}

	// refCount == 1 → delete blob
	if _, err := tx.Exec(ctx, `DELETE FROM blobs WHERE id=$1`, blobID); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "db commit error", http.StatusInternalServerError)
		return
	}

	// 4) Remove from MinIO (async best-effort)
	go func(bucket, key string) {
		ctx2 := context.Background()
		if err := s.minio.Client.RemoveObject(ctx2, bucket, key, minio.RemoveObjectOptions{}); err != nil {
			log.Printf("minio delete error: %v", err)
		}
	}(s.minio.Bucket, storageKey)

	writeJSON(w, map[string]any{"status": "deleted", "deduped": false}, http.StatusOK)
}

func (s *Server) handleShareFile(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    userID := getUserID(r)
    if userID == "" {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    fileID := strings.TrimPrefix(r.URL.Path, "/api/v1/share/")
    if fileID == "" {
        http.Error(w, "file id required", http.StatusBadRequest)
        return
    }

    ctx := r.Context()
    // Ensure file belongs to user
    var exists bool
    err := s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM files WHERE id=$1 AND owner_id=$2)", fileID, userID).Scan(&exists)
    if err != nil || !exists {
        http.Error(w, "file not found or unauthorized", http.StatusNotFound)
        return
    }

    _, err = s.pool.Exec(ctx, "UPDATE files SET is_public=true WHERE id=$1", fileID)
    if err != nil {
        http.Error(w, "db error", http.StatusInternalServerError)
        return
    }

    publicURL := fmt.Sprintf("http://localhost:8080/api/v1/public/%s", fileID)
    writeJSON(w, map[string]string{"public_url": publicURL}, http.StatusOK)
}

func (s *Server) handlePublicDownload(w http.ResponseWriter, r *http.Request) {
    fileID := strings.TrimPrefix(r.URL.Path, "/api/v1/public/")
    if fileID == "" {
        http.Error(w, "file id required", http.StatusBadRequest)
        return
    }

    ctx := r.Context()
    var storageKey, mime string
    err := s.pool.QueryRow(ctx,
        "SELECT b.storage_key, f.mime FROM files f JOIN blobs b ON f.blob_id=b.id WHERE f.id=$1 AND f.is_public=true",
        fileID).Scan(&storageKey, &mime)
    if err != nil {
        http.Error(w, "file not public or not found", http.StatusNotFound)
        return
    }

    // Increment download count
    _, _ = s.pool.Exec(ctx, "UPDATE files SET download_count = download_count + 1 WHERE id=$1", fileID)

    // Stream file from MinIO
    obj, err := s.minio.Client.GetObject(ctx, s.minio.Bucket, storageKey, minio.GetObjectOptions{})
    if err != nil {
        http.Error(w, "minio fetch error", http.StatusInternalServerError)
        return
    }
    defer obj.Close()

    w.Header().Set("Content-Type", mime)
    io.Copy(w, obj)
}

func (s *Server) handlePrivateDownload(w http.ResponseWriter, r *http.Request) {
    userID := getUserID(r)
    if userID == "" {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    fileID := strings.TrimPrefix(r.URL.Path, "/api/v1/download/")
    if fileID == "" {
        http.Error(w, "file id required", http.StatusBadRequest)
        return
    }

    ctx := r.Context()
    var storageKey, mime string
    err := s.pool.QueryRow(ctx,
        "SELECT b.storage_key, f.mime FROM files f JOIN blobs b ON f.blob_id=b.id WHERE f.id=$1 AND f.owner_id=$2",
        fileID, userID).Scan(&storageKey, &mime)
    if err != nil {
        http.Error(w, "file not found or unauthorized", http.StatusNotFound)
        return
    }

    _, _ = s.pool.Exec(ctx, "UPDATE files SET download_count = download_count + 1 WHERE id=$1", fileID)

    obj, err := s.minio.Client.GetObject(ctx, s.minio.Bucket, storageKey, minio.GetObjectOptions{})
    if err != nil {
        http.Error(w, "minio fetch error", http.StatusInternalServerError)
        return
    }
    defer obj.Close()

    w.Header().Set("Content-Type", mime)
    io.Copy(w, obj)
}

func (s *Server) handleSavings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := getUserID(r)
	if userID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()

	// 1. Total size of all files by this user
	var totalFileSize int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(SUM(size),0) FROM files WHERE owner_id=$1`, userID).Scan(&totalFileSize)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// 2. Unique blob sizes for this user
	// DISTINCT blob_id ensures duplicates aren’t double-counted
	var uniqueBlobSize int64
	err = s.pool.QueryRow(ctx, `
    SELECT COALESCE(SUM(b.size),0)
    FROM blobs b
    WHERE b.id IN (
        SELECT DISTINCT blob_id FROM files WHERE owner_id=$1
    )
`, userID).Scan(&uniqueBlobSize)
	if err == pgx.ErrNoRows {
		uniqueBlobSize = 0
	} else if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	savings := totalFileSize - uniqueBlobSize
	if savings < 0 {
		savings = 0
	}

	writeJSON(w, map[string]any{
		"total_file_size": totalFileSize,
		"unique_blob_size": uniqueBlobSize,
		"savings": savings,
	}, http.StatusOK)
}

const (
    defaultRateLimit = 2              // 2 requests/sec
    defaultQuota     = 10 * 1024 * 1024 // 10 MB per user
)

func (s *Server) checkRateLimit(userID string) bool {
    s.mu.Lock()
    defer s.mu.Unlock()

    rl, exists := s.rateLimits[userID]
    if !exists {
        rl = &RateLimiter{
            tokens:     defaultRateLimit,
            lastRefill: time.Now(),
            maxTokens:  defaultRateLimit,
            refillRate: time.Second,
        }
        s.rateLimits[userID] = rl
    }

    // refill tokens
    elapsed := time.Since(rl.lastRefill)
    if elapsed >= rl.refillRate {
        rl.tokens = rl.maxTokens
        rl.lastRefill = time.Now()
    }

    if rl.tokens > 0 {
        rl.tokens--
        return true
    }
    return false
}

func (s *Server) withLimit(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        userID := getUserID(r)
        if userID == "" {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }

        if !s.checkRateLimit(userID) {
            http.Error(w, "rate limit exceeded (2 req/sec)", http.StatusTooManyRequests)
            return
        }

        next(w, r)
    }
}

func normalize(s string) string {
	
	return s
}