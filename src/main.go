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

var (
	jwtKey           = []byte("cactusdangerous")
	database         *sql.DB
	usersStatement   *sql.Stmt
	subStatement     *sql.Stmt
	threadStatement  *sql.Stmt
	commentStatement *sql.Stmt
	voteStatement    *sql.Stmt
)

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
	ID           string `json:"ID"`
	SubName      string `json:"subName"`
	CreatedBy    string `json:"createdBy"`
	ThreadTitle  string `json:"threadTitle"`
	ThreadBody   string `json:"threadBody"`
	CreatedOn    int    `json:"createdOn"`
	URL          string `json:"url"`
	CommentCount int    `json:"commentCount"`
	Points       int    `json:"points"`
	VoteState    string `json:"voteState"`
}

// Comment structure
type Comment struct {
	ID        string    `json:"ID"`
	Body      string    `json:"body"`
	Username  string    `json:"username"`
	ThreadID  string    `json:"threadID"`
	SubName   string    `json:"subName"`
	ParentID  string    `json:"parent"`
	Children  []Comment `json:"children"`
	Points    int       `json:"points"`
	VoteState string    `json:"voteState"`
}

// Vote struct
type Vote struct {
	ID       int    `json:"ID"`
	VoteType string `json:"voteType"`
	Kind     string `json:"kind"`
	KindID   string `json:"kindID"`
	Username string `json:"username"`
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
	router.HandleFunc("/api/createthread", createThread).Methods("POST")
	router.HandleFunc("/api/getlistingdata", getListingData).Methods("POST")
	router.HandleFunc("/api/createcomment", createComment).Methods("POST")
	router.HandleFunc("/api/getcommentdata", getCommentData).Methods("POST")
	router.HandleFunc("/api/createvote", createVote).Methods("POST")
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

func getCommentCount(threadID int) (int, error) {
	var count int
	err := database.QueryRow("SELECT COUNT(*) FROM comments WHERE thread_id=?", threadID).Scan(&count)
	return count, err
}

func comparePasswords(hashedPwd []byte, plainPwd []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedPwd, plainPwd)
	if err != nil {
		return false
	}
	return true
}

func getCommentWithChildren(comment Comment, currentUserID int) (Comment, error) {
	var commentWithChildren Comment
	var commentID int
	var userID int
	var threadID int
	var subID int
	var parentID int
	err := database.QueryRow("SELECT id, body, created_by, thread_id, sub_id, parent_id FROM comments WHERE id=?", comment.ID).Scan(&commentID, &commentWithChildren.Body, &userID, &threadID, &subID, &parentID)
	commentWithChildren.ID = base10to36(commentID)
	commentWithChildren.Username, err = getUsernameFromID(userID)
	commentWithChildren.ThreadID = base10to36(threadID)
	commentWithChildren.SubName, err = getSubNameFromID(subID)
	commentWithChildren.ParentID = base10to36(parentID)
	commentWithChildren.Points, err = countPoints("comment", commentID)
	commentWithChildren.VoteState, err = getVoteState(currentUserID, "comment", commentID)
	rows, err := database.Query("SELECT id FROM comments WHERE parent_id=?", comment.ID)
	if err != nil {
		return commentWithChildren, err
	}
	defer rows.Close()
	for rows.Next() {
		var child Comment
		rows.Scan(&child.ID)
		children, err := getCommentWithChildren(child, currentUserID)
		if err != nil {
			return commentWithChildren, err
		}
		commentWithChildren.Children = append(commentWithChildren.Children, children)
	}
	return commentWithChildren, err
}

func countPoints(kind string, kindID int) (int, error) {
	var upCount int
	var downCount int
	err := database.QueryRow("SELECT COUNT (*) FROM votes WHERE vote_type='up' AND kind=? AND kind_id=?", kind, kindID).Scan(&upCount)
	err = database.QueryRow("SELECT COUNT (*) FROM votes WHERE vote_type='down' AND kind=? AND kind_id=?", kind, kindID).Scan(&downCount)
	return upCount - downCount, err
}

func getVoteState(userID int, kind string, kindID int) (string, error) {
	var voteState string
	var noVote error
	err := database.QueryRow("SELECT vote_type FROM votes WHERE user_id=? AND kind=? AND kind_id=?", userID, kind, kindID).Scan(&voteState)
	if err == sql.ErrNoRows {
		return "none", noVote
	}
	return voteState, err
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
	voteStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS votes (id INTEGER PRIMARY KEY, vote_type TEXT, kind TEXT, kind_id INTEGER, user_id INTEGER, created_on INTEGER)")
	voteStatement.Exec()
	voteStatement, _ = database.Prepare("INSERT INTO votes (vote_type, kind, kind_id, user_id, created_on) VALUES (?, ?, ?, ?, ?)")
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
		message := "Thread body cannot be more than " + strconv.Itoa(threadBodyMax) + " characters."
		http.Error(w, message, 403)
		return
	}
	subID, err := getIDFromSubName(thread.SubName)
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

func getListingData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data := map[string]string{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Invalid.", 400)
		return
	}
	kind := data["kind"]
	id := data["id"]
	currentUserID, _ := getIDFromUsername(data["currentUser"])
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
		listing.CreatedBy, err = getUsernameFromID(createdByID)
		listing.ID = base10to36(ID)
		listing.CommentCount, err = getCommentCount(ID)
		listing.Points, err = countPoints("thread", ID)
		listing.VoteState, err = getVoteState(currentUserID, "thread", ID)
		if err != nil {
			http.Error(w, "Server error.", 500)
			return
		}
		if kind == "home" && id == "" {
			listingExists = true
			allListings = append(allListings, listing)
		}
		if kind == "sub" {
			_, err = getIDFromSubName(id)
			if err == sql.ErrNoRows {
				http.Error(w, "Sub does not exist.", 404)
				return
			}
			listingExists = true
			if listing.SubName == id {
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
		message := "Comment cannot be more than " + strconv.Itoa(commentMax) + " characters."
		http.Error(w, message, 403)
		return
	}
	subID, err := getIDFromSubName(comment.SubName)
	userID, err := getIDFromUsername(comment.Username)
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

func getCommentData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data := map[string]string{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Invalid.", 400)
		return
	}
	kind := data["kind"]
	id := data["id"]
	currentUser := data["currentUser"]
	currentUserID, _ := getIDFromUsername(currentUser)
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
			commentWithChildren, err := getCommentWithChildren(comment, currentUserID)
			if err != nil {
				http.Error(w, "Server error.", 500)
				return
			}
			allComments = append(allComments, commentWithChildren)
		}
	}
	if kind == "comment" {
		commentID := base36to10(id)
		var comment Comment
		err := database.QueryRow("SELECT id FROM comments WHERE id=?", commentID).Scan(&comment.ID)
		if err != nil {
			http.Error(w, "Comment does not exist.", 404)
			return
		}
		commentWithChildren, err := getCommentWithChildren(comment, currentUserID)
		if err != nil {
			http.Error(w, "Server error.", 500)
			return
		}
		json.NewEncoder(w).Encode(commentWithChildren)
		return
	}
	json.NewEncoder(w).Encode(allComments)
}

func createVote(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var vote Vote
	err := json.NewDecoder(r.Body).Decode(&vote)
	if err != nil {
		http.Error(w, "Invalid.", 400)
		return
	}
	userID, err := getIDFromUsername(vote.Username)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	kindID := base36to10(vote.KindID)
	var existingID int
	var existingType string
	var voteState string
	now := time.Now().Unix()
	err = database.QueryRow("SELECT id, vote_type FROM votes WHERE kind=? AND kind_id=? AND user_ID=?", vote.Kind, kindID, userID).Scan(&existingID, &existingType)
	if err == sql.ErrNoRows {
		_, err = voteStatement.Exec(&vote.VoteType, &vote.Kind, &kindID, &userID, &now)
		if err != nil {
			http.Error(w, "Server error.", 500)
			return
		}
		voteState = vote.VoteType
	}
	if vote.VoteType == existingType {
		_, err = database.Exec("DELETE FROM votes WHERE id=?", existingID)
		if err != nil {
			http.Error(w, "Server error.", 500)
			return
		}
		voteState = "none"
	} else {
		_, err = database.Exec("UPDATE votes SET vote_type=?, created_on=? WHERE vote_type=? AND user_id=? AND kind=? and kind_id=?", vote.VoteType, now, existingType, userID, vote.Kind, kindID)
		if err != nil {
			http.Error(w, "Server error.", 500)
			return
		}
		voteState = vote.VoteType
	}
	points, err := countPoints(vote.Kind, kindID)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	response := map[string]interface{}{
		"voteState": voteState,
		"points":    points,
	}
	json.NewEncoder(w).Encode(response)
}
