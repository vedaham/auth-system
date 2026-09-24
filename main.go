package main

import (
	"auth-system/auth"
	"auth-system/database"
	"log"
	"os"

	"fmt"
	"net/http"

	"github.com/joho/godotenv"
)




func main() {
	database := database.ConnectDB()
	err := godotenv.Load()
	if err != nil{
		log.Fatal("error in .env file")
	}
	jwtKey := []byte(os.Getenv("JWTKEY"))
	router := http.NewServeMux()

	router.HandleFunc("/signup", auth.RegisterHandler(database))
	router.HandleFunc("/signin", auth.LoginHandler(database,jwtKey))
	router.HandleFunc("/welcome",auth.WelcomeHandler(jwtKey))

	server := http.Server{
		Addr:    ":8000",
		Handler: router,
	}
	
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}
}
