package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
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
	usernameMax     = 20
	usernameMin     = 4
	passwordMin     = 6
	validEmail      = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
	subNameMax      = 20
	validSubName    = "^[a-zA-Z0-9_]*$"
	threadTitleMax  = 100
	threadTitleMin  = 1
	threadBodyMax   = 5000
	threadBodyMin   = 0
	commentMin      = 1
	commentMax      = 5000
	urlMax          = 50
	tokenExpiration = 72 * time.Hour
)

var (
	jwtKey           = []byte("cactusdangerous")
	database         *sql.DB
	usersStatement   *sql.Stmt
	subStatement     *sql.Stmt
	threadStatement  *sql.Stmt
	commentStatement *sql.Stmt
	voteStatement    *sql.Stmt
	fileStatement    *sql.Stmt
)

// User structure
type User struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	Preferences string `json:"preferences"`
}

// Sub structure
type Sub struct {
	SubName   string `json:"subName"`
	CreatedBy string `json:"createdBy"`
	CreatedOn int    `json:"createdOn"`
}

// Thread structure
type Thread struct {
	ID           string  `json:"ID"`
	SubName      string  `json:"subName"`
	CreatedBy    string  `json:"createdBy"`
	ThreadTitle  string  `json:"threadTitle"`
	ThreadBody   string  `json:"threadBody"`
	ThreadType   string  `json:"threadType"`
	ThreadLink   string  `json:"threadLink"`
	CreatedOn    int     `json:"createdOn"`
	ThreadURL    string  `json:"threadURL"`
	ImageURL     string  `json:"imageURL"`
	CommentCount int     `json:"commentCount"`
	Points       int     `json:"points"`
	VoteState    string  `json:"voteState"`
	HotScore     float64 `json:"hotScore"`
	Kind         string  `json:"kind"`
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
	CreatedOn int       `json:"createdOn"`
	Kind      string    `json:"kind"`
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
	router.HandleFunc("/api/validate", validate).Methods("POST")
	router.HandleFunc("/api/home", home).Methods("GET")
	router.HandleFunc("/api/register", register).Methods("POST")
	router.HandleFunc("/api/login", login).Methods("POST")
	router.HandleFunc("/api/createsub", createSub).Methods("POST")
	router.HandleFunc("/api/createthread", createThread).Methods("POST")
	router.HandleFunc("/api/getlistingdata", getListingData).Methods("POST")
	router.HandleFunc("/api/createcomment", createComment).Methods("POST")
	router.HandleFunc("/api/getcommentdata", getCommentData).Methods("POST")
	router.HandleFunc("/api/createvote", createVote).Methods("POST")
	router.HandleFunc("/api/updatepref", updatePreferences).Methods("POST")
	router.HandleFunc("/api/search", search).Methods("GET")
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

func getURLFromImageID(id int) (string, error) {
	var url string
	err := database.QueryRow("SELECT url FROM files WHERE id=?", id).Scan(&url)
	return url, err
}

func titleToURL(title string) string {
	threadURL := strings.Replace(title, " ", "_", -1)
	// pattern := regexp.MustCompile(`[^a-zA-Z\d_]`)
	// threadURL = pattern.ReplaceAllString(threadURL, "")
	if len(threadURL) > urlMax {
		threadURL = threadURL[0:urlMax]
	}
	return threadURL
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

func getCommentWithChildren(comment Comment, currentUserID int, sortBy string) (Comment, error) {
	var (
		commentWithChildren Comment
		commentID           int
		userID              int
		threadID            int
		subID               int
		parentID            int
	)
	err := database.QueryRow("SELECT id, body, created_by, thread_id, sub_id, parent_id, created_on FROM comments WHERE id=?", comment.ID).Scan(&commentID, &commentWithChildren.Body, &userID, &threadID, &subID, &parentID, &commentWithChildren.CreatedOn)
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
		children, err := getCommentWithChildren(child, currentUserID, sortBy)
		if err != nil {
			return commentWithChildren, err
		}
		commentWithChildren.Children = append(commentWithChildren.Children, children)
	}
	sortComments(&commentWithChildren.Children, sortBy)
	return commentWithChildren, err
}

func countPoints(kind string, kindID int) (int, error) {
	var (
		upCount   int
		downCount int
	)
	err := database.QueryRow("SELECT COUNT (*) FROM votes WHERE vote_type='up' AND kind=? AND kind_id=?", kind, kindID).Scan(&upCount)
	err = database.QueryRow("SELECT COUNT (*) FROM votes WHERE vote_type='down' AND kind=? AND kind_id=?", kind, kindID).Scan(&downCount)
	return upCount - downCount, err
}

func getHotScore(threadID int) float64 {
	var (
		secondsInDay  = float64(86400)
		score         = float64(1)
		threadCreated float64
		now           = float64(time.Now().Unix())
	)
	database.QueryRow("SELECT created_on FROM threads WHERE id=?", threadID).Scan(&threadCreated)
	rows, _ := database.Query("SELECT created_on FROM votes WHERE vote_type='up' AND kind='thread' AND kind_id=?", threadID)
	defer rows.Close()
	for rows.Next() {
		var voteTime float64
		rows.Scan(&voteTime)
		timeBetweenThreadAndVote := voteTime - threadCreated
		days := math.Ceil(timeBetweenThreadAndVote / secondsInDay)
		// Vote score decreases in half every day. But all votes from the same
		// day have the same score as days are rounded up
		score += 1 / math.Pow(2, days)
	}
	timeBetweenThreadAndNow := now - threadCreated
	// Thread score has a half life of 2 days
	threadScore := math.Pow(0.5, (timeBetweenThreadAndNow / (secondsInDay * 2)))
	score *= threadScore
	return score
}

func getVoteState(userID int, kind string, kindID int) (string, error) {
	var (
		voteState string
		noVote    error
	)
	err := database.QueryRow("SELECT vote_type FROM votes WHERE user_id=? AND kind=? AND kind_id=?", userID, kind, kindID).Scan(&voteState)
	if err == sql.ErrNoRows {
		return "none", noVote
	}
	return voteState, err
}

func sortComments(comments *[]Comment, sortBy string) {
	if sortBy == "top" || sortBy == "bottom" {
		sort.Slice(*comments, func(i, j int) bool {
			return (*comments)[i].Points < (*comments)[j].Points
		})
		if sortBy == "top" {
			for i, j := 0, len(*comments)-1; i < j; i, j = i+1, j-1 {
				(*comments)[i], (*comments)[j] = (*comments)[j], (*comments)[i]
			}
		}
	}
	if sortBy == "old" || sortBy == "new" {
		sort.Slice(*comments, func(i, j int) bool {
			return (*comments)[i].CreatedOn < (*comments)[j].CreatedOn
		})
		if sortBy == "new" {
			for i, j := 0, len(*comments)-1; i < j; i, j = i+1, j-1 {
				(*comments)[i], (*comments)[j] = (*comments)[j], (*comments)[i]
			}
		}
	}
}

func generateTokenString(username string) (string, error) {
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(tokenExpiration).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	return tokenString, err
}

func validateAndRenewToken(tokenString string) (string, string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid  token")
		}
		return []byte("cactusdangerous"), nil
	})
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		tokenString, err := generateTokenString(claims.Username)
		return claims.Username, tokenString, err
	}
	return "", "", err
}

func isValidURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "" || u.Host != "" {
		return true
	}
	if u.Scheme == "" || u.Host == "" || u.Path == "" {
		return false
	}
	return true
}

func prepDB() {
	usersStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, created_on INTEGER, preferences TEXT)")
	usersStatement.Exec()
	usersStatement, _ = database.Prepare("INSERT INTO users (username, password, email, created_on) VALUES (?, ?, ?, ?)")
	subStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS subs (id INTEGER PRIMARY KEY, subname TEXT, created_by INTEGER, created_on INTEGER)")
	subStatement.Exec()
	subStatement, _ = database.Prepare("INSERT INTO subs (subname, created_by, created_on) VALUES (?, ?, ?)")
	threadStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS threads (id INTEGER PRIMARY KEY, sub_id INTEGER, created_by INTEGER, thread_type TEXT, thread_title TEXT, thread_body TEXT, thread_link TEXT, image_id INTEGER, created_on INTEGER)")
	threadStatement.Exec()
	threadStatement, _ = database.Prepare("INSERT INTO threads (id, sub_id, created_by, thread_type, thread_title, thread_body, thread_link, image_id, created_on) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
	commentStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, body TEXT, created_by INTEGER, thread_id INTEGER, sub_id INTEGER, parent_id INTEGER, created_on INTEGER)")
	commentStatement.Exec()
	commentStatement, _ = database.Prepare("INSERT INTO comments (id, body, created_by, thread_id, sub_id, parent_id, created_on) VALUES (?, ?, ?, ?, ?, ?, ?)")
	voteStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS votes (id INTEGER PRIMARY KEY, vote_type TEXT, kind TEXT, kind_id INTEGER, user_id INTEGER, created_on INTEGER)")
	voteStatement.Exec()
	voteStatement, _ = database.Prepare("INSERT INTO votes (vote_type, kind, kind_id, user_id, created_on) VALUES (?, ?, ?, ?, ?)")
	fileStatement, _ = database.Prepare("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, file_type TEXT, url TEXT, created_on INTEGER)")
	fileStatement.Exec()
	fileStatement, _ = database.Prepare("INSERT INTO files (id, file_type, url, created_on) VALUES (?, ?, ?, ?)")
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
	if len(user.Username) > usernameMax {
		message := "Username cannot be more than " + strconv.Itoa(usernameMax) + " characters."
		http.Error(w, message, 403)
		return
	}
	if len(user.Username) < usernameMin {
		message := "Username cannot be less than " + strconv.Itoa(usernameMin) + " characters."
		http.Error(w, message, 403)
		return
	}
	if len(user.Password) < passwordMin {
		message := "Password cannot be less than " + strconv.Itoa(passwordMin) + " characters."
		http.Error(w, message, 403)
		return
	}
	re := regexp.MustCompile(validEmail)
	if !re.MatchString(user.Email) {
		http.Error(w, "Invalid email.", 403)
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
	var preferences sql.NullString
	err = database.QueryRow("SELECT username, password, preferences FROM users WHERE username=?", user.Username).Scan(&existingUser.Username, &existingUser.Password, &preferences)
	if err != nil {
		http.Error(w, "Invalid credentials.", 401)
		return
	}
	if preferences.Valid {
		existingUser.Preferences = preferences.String
	}
	if comparePasswords([]byte(existingUser.Password), []byte(user.Password)) {
		tokenString, err := generateTokenString(user.Username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		response := map[string]string{
			"token":       tokenString,
			"username":    user.Username,
			"preferences": existingUser.Preferences,
		}
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Invalid credentials.", 401)
	}
}

func validate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var token string
	err := json.NewDecoder(r.Body).Decode(&token)
	username, newToken, err := validateAndRenewToken(token)
	if err != nil {
		http.Error(w, "Session expired. Log in again to continue.", 401)
		return
	}
	response := map[string]string{
		"token":    newToken,
		"username": username,
	}
	json.NewEncoder(w).Encode(response)
}

func createSub(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data := map[string]string{}
	err := json.NewDecoder(r.Body).Decode(&data)
	subName := data["subName"]
	token, ok := data["token"]
	if !ok || err != nil {
		http.Error(w, "Invalid.", 401)
		return
	}
	username, newToken, err := validateAndRenewToken(token)
	if err != nil {
		http.Error(w, "Session expired. Log in again to continue.", 401)
		return
	}
	if len(subName) > subNameMax {
		message := "Thread title cannot be more than " + strconv.Itoa(subNameMax) + " characters."
		http.Error(w, message, 403)
		return
	}
	re := regexp.MustCompile(validSubName)
	if !re.MatchString(subName) {
		http.Error(w, "Sub name can only have alphanumeric characters or underscore.", 403)
		return
	}
	err = database.QueryRow("SELECT subname FROM subs WHERE subname=?", subName).Scan()
	if err != sql.ErrNoRows {
		http.Error(w, "Sub exists.", 409)
		return
	}
	userID, err := getIDFromUsername(username)
	now := time.Now().Unix()
	_, err = subStatement.Exec(&subName, &userID, &now)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	response := map[string]string{
		"token":    newToken,
		"username": username,
	}
	json.NewEncoder(w).Encode(response)
}

func handleImage(r *http.Request) (int, error) {
	file, handler, err := r.FormFile("file")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	fileType := http.DetectContentType(buffer)[:5]
	if fileType != "image" {
		return 0, http.ErrBodyNotAllowed
	}
	file.Seek(0, io.SeekStart)
	var (
		lastFileID int
		fileID     int
	)
	err = database.QueryRow("SELECT id FROM files ORDER BY id DESC LIMIT 1").Scan(&lastFileID)
	if err != nil {
		fileID = 10000
	} else {
		fileID = lastFileID + 1
	}
	splitFileName := strings.Split(handler.Filename, ".")
	fileExtension := splitFileName[len(splitFileName)-1]
	fileName := base10to36(fileID) + "." + fileExtension
	url := "/img/" + fileName
	f, err := os.OpenFile("../public"+url, os.O_WRONLY|os.O_CREATE, 0666)
	defer f.Close()
	_, err = io.Copy(f, file)
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	_, err = fileStatement.Exec(&fileID, &fileType, &url, &now)
	return fileID, err
}

func createThread(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "multipart/form-data")
	err := r.ParseMultipartForm(10 << 20)
	var thread Thread
	thread.SubName = r.FormValue("subName")
	thread.ThreadTitle = r.FormValue("threadTitle")
	thread.ThreadBody = r.FormValue("threadBody")
	thread.ThreadType = r.FormValue("threadType")
	token := r.FormValue("token")
	if err != nil {
		http.Error(w, "Invalid.", 401)
		return
	}
	username, newToken, err := validateAndRenewToken(token)
	if err != nil {
		http.Error(w, "Session expired. Log in again to continue.", 401)
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
	var imageID int
	if thread.ThreadType == "image" {
		imageID, err = handleImage(r)
		if err == http.ErrBodyNotAllowed {
			http.Error(w, "Invalid file format.", 406)
			return
		}
		if err != nil {
			http.Error(w, "Server error.", 500)
			return
		}
	}
	if thread.ThreadType == "link" {
		thread.ThreadLink = r.FormValue("threadLink")
		if !isValidURL(thread.ThreadLink) {
			http.Error(w, "Invalid url.", 403)
			return
		}
	}
	subID, err := getIDFromSubName(thread.SubName)
	userID, err := getIDFromUsername(username)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	var (
		lastThreadID int
		threadID     int
	)
	err = database.QueryRow("SELECT id FROM threads ORDER BY id DESC LIMIT 1").Scan(&lastThreadID)
	if err != nil {
		threadID = 100000
	} else {
		threadID = lastThreadID + 1
	}
	now := time.Now().Unix()
	_, err = threadStatement.Exec(&threadID, &subID, &userID, &thread.ThreadType, &thread.ThreadTitle, &thread.ThreadBody, &thread.ThreadLink, &imageID, now)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	response := map[string]string{
		"threadID":  base10to36(threadID),
		"threadURL": titleToURL(thread.ThreadTitle),
		"token":     newToken,
		"username":  username,
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
	sortBy := data["sortBy"]
	currentUserID, _ := getIDFromUsername(data["currentUser"])
	var (
		allListings []Thread
		subID       int
		createdByID int
		ID          int
		imageID     int
	)
	listingExists := false
	rows, err := database.Query("SELECT id, sub_id, created_by, thread_type, thread_title, thread_link, image_id, created_on FROM threads")
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var listing Thread
		rows.Scan(&ID, &subID, &createdByID, &listing.ThreadType, &listing.ThreadTitle, &listing.ThreadLink, &imageID, &listing.CreatedOn)
		listing.SubName, err = getSubNameFromID(subID)
		listing.CreatedBy, err = getUsernameFromID(createdByID)
		listing.ID = base10to36(ID)
		listing.CommentCount, err = getCommentCount(ID)
		listing.VoteState, err = getVoteState(currentUserID, "thread", ID)
		if imageID != 0 {
			listing.ImageURL, err = getURLFromImageID(imageID)
		}
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
		if kind == "user" {
			_, err := getIDFromUsername(id)
			if err == sql.ErrNoRows {
				http.Error(w, "User does not exist.", 404)
				return
			}
			listingExists = true
			if listing.CreatedBy == id {
				allListings = append(allListings, listing)
			}
		}
		if kind == "thread" {
			if listing.ID == id {
				listing.Points, _ = countPoints("thread", ID)
				listing.ThreadURL = titleToURL(listing.ThreadTitle)
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
	if len(allListings) == 0 {
		http.Error(w, "No threads.", 404)
		return
	}
	if !listingExists {
		http.Error(w, "Thread does not exist.", 404)
		return
	}
	for i := range allListings {
		allListings[i].Points, _ = countPoints("thread", base36to10(allListings[i].ID))
		allListings[i].ThreadURL = titleToURL(allListings[i].ThreadTitle)
	}
	if sortBy == "hot" {
		for i := range allListings {
			allListings[i].HotScore = getHotScore(base36to10(allListings[i].ID))
		}
		sort.Slice(allListings, func(i, j int) bool {
			return allListings[i].HotScore > allListings[j].HotScore
		})
	}
	if sortBy == "top" || sortBy == "bottom" {
		sort.Slice(allListings, func(i, j int) bool {
			return allListings[i].Points < allListings[j].Points
		})
		if sortBy == "top" {
			for i, j := 0, len(allListings)-1; i < j; i, j = i+1, j-1 {
				allListings[i], allListings[j] = allListings[j], allListings[i]
			}
		}
	}
	if sortBy == "old" || sortBy == "new" {
		sort.Slice(allListings, func(i, j int) bool {
			return allListings[i].CreatedOn < allListings[j].CreatedOn
		})
		if sortBy == "new" {
			for i, j := 0, len(allListings)-1; i < j; i, j = i+1, j-1 {
				allListings[i], allListings[j] = allListings[j], allListings[i]
			}
		}
	}

	json.NewEncoder(w).Encode(allListings)
}

func createComment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data := map[string]string{}
	err := json.NewDecoder(r.Body).Decode(&data)
	var comment Comment
	comment.Body = data["body"]
	comment.ThreadID = data["threadID"]
	comment.SubName = data["subName"]
	comment.ParentID = data["parent"]
	token, ok := data["token"]
	if !ok || err != nil {
		http.Error(w, "Invalid.", 401)
		return
	}
	username, newToken, err := validateAndRenewToken(token)
	if err != nil {
		http.Error(w, "Session expired. Log in again to continue.", 401)
		return
	}
	comment.Username = username
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
	var (
		lastCommentID int
		commentID     int
	)
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
	json.NewEncoder(w).Encode(map[string]interface{}{"comment": comment, "token": newToken})
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
	sortBy := data["sortBy"]
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
			commentWithChildren, err := getCommentWithChildren(comment, currentUserID, sortBy)
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
		commentWithChildren, err := getCommentWithChildren(comment, currentUserID, sortBy)
		if err != nil {
			http.Error(w, "Server error.", 500)
			return
		}
		json.NewEncoder(w).Encode(commentWithChildren)
		return
	}
	if kind == "user" {
		userID, err := getIDFromUsername(id)
		if err == sql.ErrNoRows {
			http.Error(w, "User does not exist.", 404)
			return
		}
		rows, err := database.Query("SELECT id, body, thread_id, sub_id, parent_id, created_on FROM comments WHERE created_by=?", userID)
		if err != nil {
			http.Error(w, "Server error.", 500)
			return
		}
		defer rows.Close()
		var (
			commentID int
			threadID  int
			subID     int
			parentID  int
		)
		for rows.Next() {
			var comment Comment
			err = rows.Scan(&commentID, &comment.Body, &threadID, &subID, &parentID, &comment.CreatedOn)
			comment.ID = base10to36(commentID)
			comment.Username = id
			comment.ThreadID = base10to36(threadID)
			comment.SubName, err = getSubNameFromID(subID)
			comment.ParentID = base10to36(parentID)
			comment.Points, err = countPoints("comment", commentID)
			comment.VoteState, err = getVoteState(currentUserID, "comment", commentID)
			if err != nil {
				http.Error(w, "Server error.", 500)
				return
			}
			allComments = append(allComments, comment)
		}
	}
	sortComments(&allComments, sortBy)
	json.NewEncoder(w).Encode(allComments)
}

func createVote(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data := map[string]string{}
	err := json.NewDecoder(r.Body).Decode(&data)
	var vote Vote
	vote.Kind = data["kind"]
	vote.VoteType = data["voteType"]
	vote.KindID = data["kindID"]
	token, ok := data["token"]
	if !ok || err != nil {
		http.Error(w, "Invalid.", 401)
		return
	}
	username, newToken, err := validateAndRenewToken(token)
	if err != nil {
		http.Error(w, "Session expired. Log in again to continue.", 401)
		return
	}
	userID, err := getIDFromUsername(username)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	kindID := base36to10(vote.KindID)
	var (
		existingID   int
		existingType string
		voteState    string
	)
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
		"token":     newToken,
		"voteState": voteState,
		"points":    points,
	}
	json.NewEncoder(w).Encode(response)
}

func updatePreferences(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	data := map[string]interface{}{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(data["preferences"])
	preferences := buf.String()
	preferences = preferences[:len(preferences)-1]
	token, ok := data["token"].(string)
	if !ok || err != nil {
		http.Error(w, "Invalid.", 401)
		return
	}
	username, newToken, err := validateAndRenewToken(token)
	if err != nil {
		http.Error(w, "Session expired. Log in again to continue.", 401)
		return
	}
	userID, err := getIDFromUsername(username)
	_, err = database.Exec("UPDATE users SET preferences=? WHERE id=?", preferences, userID)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	response := map[string]string{
		"token":       newToken,
		"preferences": preferences,
	}
	json.NewEncoder(w).Encode(response)
}

func search(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := r.URL.Query()
	query := params.Get("query")
	// kind := params.Get("kind")
	subName := params.Get("in")
	username := params.Get("by")
	rankedResults, err := searchDB(query, subName, username)
	if err == ErrNoMatches {
		http.Error(w, "No matching search results.", 404)
		return
	}
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	data, err := getDataForSearchResults(rankedResults)
	if err != nil {
		http.Error(w, "Server error.", 500)
		return
	}
	json.NewEncoder(w).Encode(data)
}
