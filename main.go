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
)

type Server struct {
	pool      *pgxpool.Pool
	jwtSecret string
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

	srv := &Server{
		pool:      pool,
		jwtSecret: jwtSecret,
	}

	http.HandleFunc("/api/v1/signup", srv.handleSignup)
	http.HandleFunc("/api/v1/login", srv.handleLogin)

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

func normalize(s string) string {
	
	return s
}