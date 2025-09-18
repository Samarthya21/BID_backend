package models

import (
	"context"
)

type User struct {
	ID           string
	Email        string
	PasswordHash string
	Name         string
}

type DB interface {
	UserExists(ctx context.Context, email string) bool
	InsertUser(ctx context.Context, id, email, hash, name string) error
	GetUserByEmail(ctx context.Context, email string) (User, error)
	CreateJWT(id, email, secret string) (string, error)
}
