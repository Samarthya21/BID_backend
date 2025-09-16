package main

import (
	"context"
	"encoding/json"
	
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"crypto/sha256"
	"fmt"
	"io"
	"mime/multipart"
	

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

func withCORS(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
        w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
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
	}

	http.HandleFunc("/api/v1/signup", withCORS(srv.handleSignup))
	http.HandleFunc("/api/v1/login", withCORS(srv.handleLogin))
	http.HandleFunc("/api/v1/upload", withCORS(srv.withAuth(srv.handleUpload)))
	http.HandleFunc("/api/v1/files", withCORS(srv.withAuth(srv.handleListFiles)))


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
	// (TODO: extract userID from JWT)
	// for testing purpose here we use a fixed userID - alice test@1gmail.com
	userID := getUserID(r)
	if userID == "" {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
	}

	err := r.ParseMultipartForm(32 << 20) 
	if err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	var responses []UploadResponse
	for _, files := range r.MultipartForm.File {
		for _, fh := range files {
			res, err := s.saveFile(userID, fh)
			if err != nil {
				http.Error(w, "upload error: "+err.Error(), http.StatusInternalServerError)
				return
			}
			responses = append(responses, res)
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


func normalize(s string) string {
	
	return s
}