package auth

import "time"

type User struct {
	Id            int       `json:"id"`
	Email         string    `json:"email"`
	PasswordHash  string    `json:"password_hash"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
}

type RefreshToken struct {
	Id        int       `json:"id"`
	UserId    User      `json:"user_id"`
	TokenHash string    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

type PasswordReset struct {
	Id        int       `json:"id"`
	UserId    User      `json:"user_id"`
	TokenHash string    `json:"token_hash"`
	ExpiresAt time.Time `json:" expires_at"`
	Used      bool      `json:"used"`
}
