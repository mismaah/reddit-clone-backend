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
	"github.com/martinlindhe/base36"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/cors" // Remove in production
	"golang.org/x/crypto/bcrypt"
)

const (
	subNameMax     = 20
	validSubName   = "^[a-zA-Z0-9_]*$"
	threadTitleMax = 100
	threadTitleMin = 1
	threadBodyMax  = 5000
	threadBodyMin  = 0
	commentMin     = 1
	commentMax     = 5000
	urlMax         = 50
)

var jwtKey = []byte("cactusdangerous")
var database *sql.DB
var usersStatement *sql.Stmt
var subStatement *sql.Stmt
var threadStatement *sql.Stmt
var commentStatement *sql.Stmt

// User structure
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// Sub structure
type Sub struct {
	SubName   string `json:"subName"`
	CreatedBy string `json:"createdBy"`
	CreatedOn int    `json:"createdOn"`
}

// Thread structure
type Thread struct {
	ID          string `json:"ID"`
	SubName     string `json:"subName"`
	CreatedBy   string `json:"createdBy"`
	ThreadTitle string `json:"threadTitle"`
	ThreadBody  string `json:"threadBody"`
	CreatedOn   int    `json:"createdOn"`
	URL         string `json:"url"`
}

// Comment structure
type Comment struct {
	ID       string    `json:"ID"`
	Body     string    `json:"body"`
	Username string    `json:"username"`
	ThreadID string    `json:"threadID"`
	SubName  string    `json:"subName"`
	ParentID string    `json:"parent"`
	Children []Comment `json:"children"`
}

// Claims structure
type Claims struct {
	Username string `json:"username"`
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
	router.HandleFunc("/api/getlistingdata/{kind}/{id}", getListingData).Methods("GET")
	router.HandleFunc("/api/createcomment", createComment).Methods("POST")
	router.HandleFunc("/api/getcommentdata/{kind}/{id}", getCommentData).Methods("GET")
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

func getSubNameFromID(id int) (string, error) {
	var subName string
	err := database.QueryRow("SELECT subname FROM subs WHERE id=?", id).Scan(&subName)
	return subName, err
}

func getIDFromSubName(subName string) (int, error) {
	var id int
	err := database.QueryRow("SELECT id FROM subs WHERE subname=?", subName).Scan(&id)
	return id, err
}

func getUsernameFromID(id int) (string, error) {
	var username string
	err := database.QueryRow("SELECT username FROM users WHERE id=?", id).Scan(&username)
	return username, err
}

func getIDFromUsername(username string) (int, error) {
	var id int
	err := database.QueryRow("SELECT id FROM users WHERE username=?", username).Scan(&id)
	return id, err
}

func titleToURL(title string) string {
	url := strings.Replace(title, " ", "_", -1)
	pattern := regexp.MustCompile(`[^a-zA-Z\d_]`)
	url = pattern.ReplaceAllString(url, "")
	if len(url) > urlMax {
		url = url[0:urlMax]
	}
	return url
}

func prepDB() {
	usersStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, created_on INTEGER)")
	usersStatement.Exec()
	usersStatement, _ = database.Prepare("INSERT INTO users (username, password, email, created_on) VALUES (?, ?, ?, ?)")
	subStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS subs (id INTEGER PRIMARY KEY, subname TEXT, created_by INTEGER, created_on INTEGER)")
	subStatement.Exec()
	subStatement, _ = database.Prepare("INSERT INTO subs (subname, created_by, created_on) VALUES (?, ?, ?)")
	threadStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS threads (id INTEGER PRIMARY KEY, sub_id INTEGER, created_by INTEGER, thread_title TEXT, thread_body TEXT, created_on INTEGER)")
	threadStatement.Exec()
	threadStatement, _ = database.Prepare("INSERT INTO threads (id, sub_id, created_by, thread_title, thread_body, created_on) VALUES (?, ?, ?, ?, ?, ?)")
	commentStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, body TEXT, created_by INTEGER, thread_id INTEGER, sub_id INTEGER, parent_id INTEGER, created_on INTEGER)")
	commentStatement.Exec()
	commentStatement, _ = database.Prepare("INSERT INTO comments (id, body, created_by, thread_id, sub_id, parent_id, created_on) VALUES (?, ?, ?, ?, ?, ?, ?)")
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
	err = database.QueryRow("SELECT username FROM users WHERE username=?", user.Username).Scan()
	if err != sql.ErrNoRows {
		http.Error(w, "Username not available.", 409)
		return
	}
	err = database.QueryRow("SELECT email FROM users WHERE email=?", user.Email).Scan()
	if err != sql.ErrNoRows {
		http.Error(w, "An account has already been registered with the email entered.", 409)
		return
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
	var existingUser User
	err = database.QueryRow("SELECT username, password FROM users WHERE username=?", user.Username).Scan(&existingUser.Username, &existingUser.Password)
	if err != nil {
		http.Error(w, "Invalid credentials.", 401)
		return
	}
	if comparePasswords([]byte(existingUser.Password), []byte(user.Password)) {
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
			"username": user.Username,
		}
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Invalid credentials.", 401)
	}
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
	var sub Sub
	err := json.NewDecoder(r.Body).Decode(&sub)
	if err != nil {
		http.Error(w, "Invalid.", 400)
		return
	}
	if len(sub.SubName) > subNameMax {
		message := "Thread title cannot be more than " + strconv.Itoa(subNameMax) + " characters."
		http.Error(w, message, 403)
		return
	}
	re := regexp.MustCompile(validSubName)
	if !re.MatchString(sub.SubName) {
		http.Error(w, "Sub name can only have alphanumeric characters or underscore.", 403)
		return
	}
	err = database.QueryRow("SELECT subname FROM subs WHERE subname=?", sub.SubName).Scan()
	if err != sql.ErrNoRows {
		http.Error(w, "Sub exists.", 409)
		return
	}
	var userID int
	err = database.QueryRow("SELECT id FROM users WHERE username=?", sub.CreatedBy).Scan(&userID)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	now := time.Now().Unix()
	subStatement.Exec(&sub.SubName, &userID, &now)
}

func getSubData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	subName := vars["subname"]
	var createdBy int
	err := database.QueryRow("Select created_by FROM subs WHERE subname=?", subName).Scan(&createdBy)
	if err != nil {
		http.Error(w, "Sub does not exist.", 404)
		return
	}
	response := map[string]string{
		"createdBy": strconv.Itoa(createdBy),
	}
	json.NewEncoder(w).Encode(response)
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
	subID, err := getIDFromSubName(thread.SubName)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	userID, err := getIDFromUsername(thread.CreatedBy)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	var lastThreadID int
	var threadID int
	err = database.QueryRow("SELECT id FROM threads ORDER BY id DESC LIMIT 1").Scan(&lastThreadID)
	if err != nil {
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
	response := map[string]string{
		"threadID": base10to36(threadID),
		"url":      titleToURL(thread.ThreadTitle),
	}
	json.NewEncoder(w).Encode(response)
}

func getThreadData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	threadID64 := vars["threadid"]
	threadID := base36to10(threadID64)
	var thread Thread
	var subID int
	var createdByID int
	err := database.QueryRow("SELECT sub_id, created_by, thread_title, thread_body, created_on FROM threads WHERE id = ?", threadID).Scan(&subID, &createdByID, &thread.ThreadTitle, &thread.ThreadBody, &thread.CreatedOn)
	if err != nil {
		http.Error(w, "Thread does not exist.", 404)
		return
	}
	thread.ID = threadID64
	thread.SubName, err = getSubNameFromID(subID)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	thread.CreatedBy, err = getUsernameFromID(createdByID)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	json.NewEncoder(w).Encode(thread)
}

func getListingData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	kind := vars["kind"]
	id := vars["id"]
	var allListings []Thread
	var subID int
	var createdByID int
	var ID int
	listingExists := false
	rows, err := database.Query("SELECT id, sub_id, created_by, thread_title, created_on FROM threads")
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var listing Thread
		rows.Scan(&ID, &subID, &createdByID, &listing.ThreadTitle, &listing.CreatedOn)
		listing.URL = titleToURL(listing.ThreadTitle)
		listing.SubName, err = getSubNameFromID(subID)
		if err != nil {
			http.Error(w, "Server error.", 500)
			return
		}
		listing.CreatedBy, err = getUsernameFromID(createdByID)
		if err != nil {
			http.Error(w, "Server error.", 500)
			return
		}
		listing.ID = base10to36(ID)
		if kind == "home" && id == "na" {
			listingExists = true
			allListings = append(allListings, listing)
		}
		if kind == "sub" {
			if listing.SubName == id {
				listingExists = true
				allListings = append(allListings, listing)
			}
		}
		if kind == "thread" {
			if listing.ID == id {
				err = database.QueryRow("SELECT thread_body FROM threads WHERE id=?", base36to10(id)).Scan(&listing.ThreadBody)
				if err != nil {
					http.Error(w, "Server error.", 500)
					return
				}
				listingExists = true
				json.NewEncoder(w).Encode(listing)
				return
			}
		}
	}
	if !listingExists {
		http.Error(w, "Thread does not exist.", 404)
		return
	}
	json.NewEncoder(w).Encode(allListings)
}

func createComment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var comment Comment
	err := json.NewDecoder(r.Body).Decode(&comment)
	if err != nil {
		http.Error(w, "Invalid.", 400)
		return
	}
	if len(comment.Body) < commentMin {
		http.Error(w, "Comment cannot be empty.", 403)
		return
	}
	if len(comment.Body) > commentMax {
		message := "Thread title cannot be more than " + strconv.Itoa(commentMax) + " characters."
		http.Error(w, message, 403)
		return
	}
	subID, err := getIDFromSubName(comment.SubName)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	userID, err := getIDFromUsername(comment.Username)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	threadID := base36to10(comment.ThreadID)
	var lastCommentID int
	var commentID int
	err = database.QueryRow("SELECT id FROM comments ORDER BY id DESC LIMIT 1").Scan(&lastCommentID)
	if err != nil {
		commentID = 1000000
	} else {
		commentID = lastCommentID + 1
	}
	var parentID int
	if comment.ParentID != "" {
		parentID = base36to10(comment.ParentID)
	}
	now := time.Now().Unix()
	_, err = commentStatement.Exec(&commentID, &comment.Body, &userID, &threadID, &subID, &parentID, now)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	comment.ID = base10to36(commentID)
	json.NewEncoder(w).Encode(comment)
}

func getCommentWithChildren(comment Comment) (Comment, error) {
	var commentWithChildren Comment
	var userID int
	var commentID int
	err := database.QueryRow("SELECT id, body, created_by FROM comments WHERE id=?", comment.ID).Scan(&commentID, &commentWithChildren.Body, &userID)
	if err != nil {
		return commentWithChildren, err
	}
	commentWithChildren.ID = base10to36(commentID)
	commentWithChildren.Username, err = getUsernameFromID(userID)
	if err != nil {
		return commentWithChildren, err
	}
	rows, err := database.Query("SELECT id FROM comments WHERE parent_id=?", comment.ID)
	if err != nil {
		return commentWithChildren, err
	}
	defer rows.Close()
	for rows.Next() {
		var child Comment
		rows.Scan(&child.ID)
		children, err := getCommentWithChildren(child)
		if err != nil {
			return commentWithChildren, err
		}
		commentWithChildren.Children = append(commentWithChildren.Children, children)
	}
	return commentWithChildren, err
}

func getCommentData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	kind := vars["kind"]
	id := vars["id"]
	var allComments []Comment
	if kind == "thread" {
		threadID := base36to10(id)
		rows, err := database.Query("SELECT id FROM comments WHERE thread_id=? AND parent_id=0", threadID)
		if err != nil {
			http.Error(w, "Server error.", 500)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var comment Comment
			rows.Scan(&comment.ID)
			commentWithChildren, err := getCommentWithChildren(comment)
			if err != nil {
				http.Error(w, "Server error.", 500)
				return
			}
			allComments = append(allComments, commentWithChildren)
		}
	}
	json.NewEncoder(w).Encode(allComments)
}
