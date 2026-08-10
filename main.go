package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	_"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

const (
	user = "postgres"
	dbname = "authdb"
	password = "postgres@007"
	host = "localhost"
	port = 5432
)

func initDB() {
	var err error

	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s " + "password=%s dbname=%s sslmode=disable",host,port,user,password,dbname)
	// connect to the postgres db
	db, err = sql.Open("postgres",psqlInfo)
	if err != nil{
		fmt.Println("Error connecting database",err)
	}
	fmt.Println(psqlInfo)
	
}

type User struct {
	Id int `json:"id" db:"id"`
	Username string `json:"username" db:"username"`
	Password string `json:"password" db:"password"`
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	// Parse and decode the request body into user struct
	user := &User{}
	err := json.NewDecoder(r.Body).Decode(user)
	if err != nil{
		http.Error(w,"error reading json",http.StatusBadRequest)
		return
	}

	// salt and hash the password using bcrypt algorithm
	hashedPassword,err := bcrypt.GenerateFromPassword([]byte(user.Password),8)

	if err := db.Ping(); err != nil {
    fmt.Println("Ping failed:", err)
}
	// Insert the username along with hashed password
	if _,err := db.Query("INSERT INTO users(username,password) VALUES($1,$2)",user.Username,string(hashedPassword));err != nil{
		fmt.Println("Database err:",err)
		http.Error(w,"internal server error",http.StatusInternalServerError)
		return
	}
}

func Signin(w http.ResponseWriter, r *http.Request){
	// parse and decode the request body in user struct
	user := &User{}
	err := json.NewDecoder(r.Body).Decode(user)
	if err != nil{
		http.Error(w,"unable to parse json",http.StatusBadRequest)
		return
	}

	// Getting the existing entery present in the database
	result := db.QueryRow("SELECT password FROM users WHERE username=$1",user.Username)
	// if err != nil{
	// 	http.Error(w,"unable to get inforamtion from database",http.StatusInternalServerError)
	// 	return
	// }

	storedUser := User{}

	// store the obtained password in 'storedcreds'
	err = result.Scan(&storedUser.Password)
	if err != nil{
		if err == sql.ErrNoRows{
			http.Error(w,"user unauthorized",http.StatusUnauthorized)
			return
		}
		http.Error(w,"internal server error",http.StatusInternalServerError)
		return
	}

	// compare the stored password with the user password
	if err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password),[]byte(user.Password));err != nil{
		http.Error(w,"unauthorized user",http.StatusUnauthorized)
		return
	}

}

func main(){
	router := http.NewServeMux()
	
	router.HandleFunc("/signup",SignUp)
	router.HandleFunc("/signin",Signin)
	
	server := http.Server{
		Addr: ":8000",
		Handler: router,
	}
	initDB()
	err := server.ListenAndServe()
	if err != nil{
		fmt.Println(err)
	}
}