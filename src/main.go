package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/cors" // Remove in production
	"golang.org/x/crypto/bcrypt"
)

const (
	subNameMax   = 20
	validSubName = "^[a-zA-Z0-9_]*$"
)

var jwtKey = []byte("cactusdangerous")
var database *sql.DB
var usersStatement *sql.Stmt
var subStatement *sql.Stmt

// User structure
type User struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
	Email    string `json:"Email"`
}

// CreateSub structure
type CreateSub struct {
	Subname   string `json:"Subname"`
	CreatedBy string `json:"CreatedBy"`
}

// Claims structure
type Claims struct {
	Username string `json:"Username"`
	jwt.StandardClaims
}

func main() {
	database, _ = sql.Open("sqlite3", "./database.db")
	prepDB()
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/api/home", home).Methods("GET")
	router.HandleFunc("/api/register", register).Methods("POST")
	router.HandleFunc("/api/login", login).Methods("POST")
	router.HandleFunc("/api/createsub", createsub).Methods("POST")
	router.HandleFunc("/api/getsubdata/{subname}", getsubdata).Methods("GET")
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("../public")))
	handler := cors.Default().Handler(router) // remove in production
	log.Println("http server started on :8000")
	err := http.ListenAndServe(":8000", handler) // change handler to router in production
	// err := http.ListenAndServe(":8000", handler) in production
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func prepDB() {
	usersStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, created_on INTEGER)")
	usersStatement.Exec()
	usersStatement, _ = database.Prepare("INSERT INTO users (username, password, email, created_on) VALUES (?, ?, ?, ?)")
	subStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS subs (id INTEGER PRIMARY KEY, subname TEXT, created_by INTEGER, created_on INTEGER)")
	subStatement.Exec()
	subStatement, _ = database.Prepare("INSERT INTO subs (subname, created_by, created_on) VALUES (?, ?, ?)")
}

func home(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rows, err := database.Query("SELECT subname FROM subs")
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	var allSubs []string
	defer rows.Close()
	for rows.Next() {
		var sub string
		rows.Scan(&sub)
		allSubs = append(allSubs, sub)
	}
	json.NewEncoder(w).Encode(allSubs)
}

func register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid.", 400)
		return
	}
	rows, _ := database.Query("SELECT username, password, email FROM users")
	defer rows.Close()
	for rows.Next() {
		var v User
		rows.Scan(&v.Username, &v.Password, &v.Email)
		if user.Username == v.Username {
			http.Error(w, "Username not available.", 409)
			return
		}
		if user.Email == v.Email {
			http.Error(w, "An account has already been registered with the email entered.", 409)
			return
		}
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	user.Password = string(hashedPassword)
	now := time.Now().Unix()
	usersStatement.Exec(&user.Username, &user.Password, &user.Email, now)
}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid credentials.", 401)
		return
	}
	rows, _ := database.Query("SELECT username, password, email FROM users")
	defer rows.Close()
	for rows.Next() {
		var v User
		rows.Scan(&v.Username, &v.Password, &v.Email)
		if user.Username == v.Username || user.Email == v.Email {
			if comparePasswords([]byte(v.Password), []byte(user.Password)) {
				expirationTime := time.Now().Add(120 * time.Minute)
				claims := &Claims{
					Username: user.Username,
					StandardClaims: jwt.StandardClaims{
						ExpiresAt: expirationTime.Unix(),
					},
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, err := token.SignedString(jwtKey)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				response := map[string]string{
					"token":    tokenString,
					"username": v.Username,
				}
				json.NewEncoder(w).Encode(response)
				return
			}
		}
	}
	http.Error(w, "Invalid credentials.", 401)
}

func comparePasswords(hashedPwd []byte, plainPwd []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedPwd, plainPwd)
	if err != nil {
		return false
	}
	return true
}

func createsub(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var createSub CreateSub
	err := json.NewDecoder(r.Body).Decode(&createSub)
	if err != nil {
		http.Error(w, "Invalid.", 400)
		return
	}
	if len(createSub.Subname) > 20 {
		http.Error(w, "Sub name cannot be more than 20 characters.", 403)
		return
	}
	re := regexp.MustCompile(validSubName)
	if !re.MatchString(createSub.Subname) {
		http.Error(w, "Sub name can only have alphanumeric characters or underscore.", 403)
		return
	}
	rows, err := database.Query("SELECT subname FROM subs")
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var currentSubName string
		rows.Scan(&currentSubName)
		if strings.ToLower(currentSubName) == strings.ToLower(createSub.Subname) {
			http.Error(w, "Sub exists.", 409)
			return
		}
	}
	urows, err := database.Query("SELECT id, username FROM users")
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	defer urows.Close()
	var matchID int
	for urows.Next() {
		var id int
		var userName string
		urows.Scan(&id, &userName)
		if userName == createSub.CreatedBy {
			matchID = id
		}
	}
	now := time.Now().Unix()
	subStatement.Exec(&createSub.Subname, &matchID, now)
}

func getsubdata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	subname := vars["subname"]
	rows, err := database.Query("SELECT subname, created_by FROM subs")
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var currentSubName string
		var createdBy int
		rows.Scan(&currentSubName, &createdBy)
		if currentSubName == subname {
			response := map[string]string{
				"createdBy": strconv.Itoa(createdBy),
			}
			json.NewEncoder(w).Encode(response)
			return
		}
	}
	http.Error(w, "Sub does not exist.", 404)
}
