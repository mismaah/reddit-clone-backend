package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/martinlindhe/base36"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/cors" // Remove in production
	"golang.org/x/crypto/bcrypt"
)

const (
	subNameMax     = 20
	validSubName   = "^[a-zA-Z0-9_]*$"
	threadTitleMax = 50
	threadTitleMin = 1
	threadBodyMax  = 5000
	threadBodyMin  = 0
)

var jwtKey = []byte("cactusdangerous")
var database *sql.DB
var usersStatement *sql.Stmt
var subStatement *sql.Stmt
var threadStatement *sql.Stmt

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

// Thread structure
type Thread struct {
	ID          string `json:"ID"`
	Subname     string `json:"subname"`
	CreatedBy   string `json:"createdBy"`
	ThreadTitle string `json:"threadTitle"`
	ThreadBody  string `json:"threadBody"`
	CreatedOn   int    `json:"createdOn"`
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
	router.HandleFunc("/api/createsub", createSub).Methods("POST")
	router.HandleFunc("/api/getsubdata/{subname}", getSubData).Methods("GET")
	router.HandleFunc("/api/createthread", createThread).Methods("POST")
	router.HandleFunc("/api/getthreaddata/{threadid}", getThreadData).Methods("GET")
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("../public")))
	handler := cors.Default().Handler(router) // remove in production
	log.Println("http server started on :8000")
	err := http.ListenAndServe(":8000", handler) // change handler to router in production
	// err := http.ListenAndServe(":8000", handler) in production
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func base10to36(numBase10 int) string {
	return strings.ToLower(base36.Encode(uint64(numBase10)))
}

func base36to10(numBase36 string) int {
	return int(base36.Decode(strings.ToUpper(numBase36)))
}

func prepDB() {
	usersStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, created_on INTEGER)")
	usersStatement.Exec()
	usersStatement, _ = database.Prepare("INSERT INTO users (username, password, email, created_on) VALUES (?, ?, ?, ?)")
	subStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS subs (id INTEGER PRIMARY KEY, subname TEXT, created_by INTEGER, created_on INTEGER)")
	subStatement.Exec()
	subStatement, _ = database.Prepare("INSERT INTO subs (subname, created_by, created_on) VALUES (?, ?, ?)")
	threadStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS threads (id INTEGER PRIMARY KEY, sub_id INTEGER, created_by INTEGER, threadtitle TEXT, threadbody TEXT, created_on INTEGER)")
	threadStatement.Exec()
	threadStatement, _ = database.Prepare("INSERT INTO threads (id, sub_id, created_by, threadtitle, threadbody, created_on) VALUES (?, ?, ?, ?, ?, ?)")
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

func createSub(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var createSub CreateSub
	err := json.NewDecoder(r.Body).Decode(&createSub)
	if err != nil {
		http.Error(w, "Invalid.", 400)
		return
	}
	if len(createSub.Subname) > subNameMax {
		message := "Thread title cannot be more than " + strconv.Itoa(subNameMax) + " characters."
		http.Error(w, message, 403)
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

func getSubData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	subName := vars["subName"]
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
		if currentSubName == subName {
			response := map[string]string{
				"createdBy": strconv.Itoa(createdBy),
			}
			json.NewEncoder(w).Encode(response)
			return
		}
	}
	http.Error(w, "Sub does not exist.", 404)
}

func createThread(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var thread Thread
	err := json.NewDecoder(r.Body).Decode(&thread)
	if err != nil {
		http.Error(w, "Invalid.", 400)
		return
	}
	if len(thread.ThreadTitle) < threadTitleMin {
		http.Error(w, "Thread title cannot be empty.", 403)
		return
	}
	if len(thread.ThreadTitle) > threadTitleMax {
		message := "Thread title cannot be more than " + strconv.Itoa(threadTitleMax) + " characters."
		http.Error(w, message, 403)
		return
	}
	if len(thread.ThreadBody) > threadBodyMax {
		message := "Thread title cannot be more than " + strconv.Itoa(threadBodyMax) + " characters."
		http.Error(w, message, 403)
		return
	}
	srows, err := database.Query("SELECT id, subname FROM subs")
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	defer srows.Close()
	var subID int
	for srows.Next() {
		var id int
		var subName string
		srows.Scan(&id, &subName)
		if subName == thread.Subname {
			subID = id
		}
	}
	urows, err := database.Query("SELECT id, username FROM users")
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	defer urows.Close()
	var userID int
	for urows.Next() {
		var id int
		var userName string
		urows.Scan(&id, &userName)
		if userName == thread.CreatedBy {
			userID = id
		}
	}
	var lastThreadID int
	var threadID int
	err = database.QueryRow("SELECT id FROM threads ORDER BY id DESC LIMIT 1").Scan(&lastThreadID)
	if err != nil {
		fmt.Println(err)
		threadID = 100000
	} else {
		threadID = lastThreadID + 1
	}
	now := time.Now().Unix()
	_, err = threadStatement.Exec(&threadID, &subID, &userID, &thread.ThreadTitle, &thread.ThreadBody, now)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	json.NewEncoder(w).Encode(base10to36(threadID))
}

func getThreadData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	threadID64 := vars["threadid"]
	threadID := base36to10(threadID64)
	var thread Thread
	var subID int
	var createdByID int
	err := database.QueryRow("SELECT sub_id, created_by, threadtitle, threadbody, created_on FROM threads WHERE id = ?", threadID).Scan(&subID, &createdByID, &thread.ThreadTitle, &thread.ThreadBody, &thread.CreatedOn)
	if err != nil {
		http.Error(w, "Thread does not exist.", 404)
		return
	}
	thread.ID = threadID64
	err = database.QueryRow("SELECT subname FROM subs WHERE id=?", subID).Scan(&thread.Subname)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	err = database.QueryRow("SELECT username FROM users WHERE id=?", createdByID).Scan(&thread.CreatedBy)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	json.NewEncoder(w).Encode(thread)
}
