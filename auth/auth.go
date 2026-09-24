package auth

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	
	"time"

	"github.com/golang-jwt/jwt/v5"
	
	"golang.org/x/crypto/bcrypt"
)

type Claims struct{
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func register(db *sql.DB,w http.ResponseWriter,r *http.Request){
	user := &User{}
	err := json.NewDecoder(r.Body).Decode(user)
	if err != nil{
		log.Println("err: ",err)
		http.Error(w,"Error decoding request",http.StatusBadRequest)
		return
	}

	hashedPassword,err := bcrypt.GenerateFromPassword([]byte(user.PasswordHash),8)
	if err != nil{
		http.Error(w,"error hashing password",http.StatusInternalServerError)
		return
	}

	query := "INSERT INTO users(id,email,password_hash,email_verified,created_at) VALUES($1,$2,$3,$4,$5)"
	_,err = db.Exec(query,user.Id,user.Email,string(hashedPassword),user.EmailVerified,user.CreatedAt)
	if err != nil{
		log.Println("err: ",err)
		http.Error(w,"error registering user",http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type","application/json")
	json.NewEncoder(w).Encode(map[string]string{"message":"user registered"})
}

func RegisterHandler(db *sql.DB)http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request) {
		register(db,w,r)
	}
}

func login(db *sql.DB,w http.ResponseWriter,r *http.Request,jwtKey []byte){
	
	
	user := &User{}
	err := json.NewDecoder(r.Body).Decode(user)
	if err !=nil{
		log.Println("err: ",err)
		http.Error(w,"error decoding request",http.StatusBadRequest)
		return
	}

	query := "SELECT password_hash FROM users WHERE email=$1"
	result := db.QueryRow(query,user.Email)
	if err != nil{
		log.Println("err: ",err)
		http.Error(w,"internal server error",http.StatusInternalServerError)
		return 
	}

	storedUser := &User{}
	err = result.Scan(&storedUser.PasswordHash)
	if err != nil{
		if err == sql.ErrNoRows{
			http.Error(w,"unauthorized user",http.StatusUnauthorized)
			return
		}
		http.Error(w,"internal server error",http.StatusInternalServerError)
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(storedUser.PasswordHash),[]byte(user.PasswordHash));err != nil{
		http.Error(w,"incorrect password",http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Email: user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256,claims)

	tokenString,err := token.SignedString([]byte(jwtKey))
	if err != nil{
		log.Println("err: ",err)
		http.Error(w,"error creating token",http.StatusInternalServerError)
		return 
	}

	http.SetCookie(w,&http.Cookie{
		Name: "token",
		Value: tokenString,
		Expires: expirationTime,
	})

	w.Header().Set("Content-Type","application/json")
	json.NewEncoder(w).Encode(map[string]string{"message":"you are log in"})

}

func LoginHandler(db *sql.DB,jwtKey []byte)http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request) {
		login(db,w,r,jwtKey)
	}
}


// Welcom
func welcome(w http.ResponseWriter,r *http.Request,jwtKey []byte){
	c,err := r.Cookie("token")
	if err != nil{
		if err == http.ErrNoCookie{
			log.Println("err: ",err)
			http.Error(w,"error no cookie",http.StatusUnauthorized)
			return 
		}
		http.Error(w,"err reading cookie",http.StatusBadRequest)
		return 
	}

	tknStr := c.Value
	claims := &Claims{}

	tkn,err := jwt.ParseWithClaims(tknStr,claims,func(token *jwt.Token)(any,error){
		return jwtKey,nil
	})

	if err != nil{
		if err == jwt.ErrSignatureInvalid{
			log.Println("err: ",err)
			http.Error(w,"signature invalid",http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return

	}
	if !tkn.Valid{
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	fmt.Fprintf(w, "Welcome %s!", claims.Email)
}

func WelcomeHandler(jwtKey []byte)http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request) {
		welcome(w,r,jwtKey)
	}
}



// Refresh token
func refresh(w http.ResponseWriter,r *http.Request,jwtKey []byte){
	c,err := r.Cookie("token")
	if err != nil{
		if err == http.ErrNoCookie{
			log.Println("err: ",err)
			http.Error(w,"error no cookie",http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tknStr := c.Value
	claims := &Claims{}
	tkn,err := jwt.ParseWithClaims(tknStr,claims,func(t *jwt.Token) (any, error) {
		return jwtKey,nil
	})
	if err != nil{
		if err == jwt.ErrSignatureInvalid{
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if time.Until(claims.ExpiresAt.Time) > 30*time.Second{
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w,&http.Cookie{
		Name: "token",
		Value: tokenString,
		Expires: expirationTime,
	})
}

func RefreshHandler(jwt []byte)http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request) {
		refresh(w,r,jwt)
	}
}