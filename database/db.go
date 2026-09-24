package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func ConnectDB() *sql.DB{
	err := godotenv.Load()
	if err != nil{
		log.Fatal("Error loading .env file")

	}
	dbUser := os.Getenv("DB_USER")
 	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbDriver := os.Getenv("DB_DRIVER")
	host := os.Getenv("HOST")
	port := os.Getenv("PORT")


	connStr := fmt.Sprintf("host=%s port=%s user=%s "+ "password=%s dbname=%s sslmode=disable",host,port,dbUser,dbPassword,dbName)

	db,err := sql.Open(dbDriver,connStr)
	if err != nil{
		panic(err)
	}
	fmt.Println("Connected to database")
	

	err = db.Ping()
	if err != nil{
		db.Close()
		log.Println("err: ",err)
	}

	return db 
 
}