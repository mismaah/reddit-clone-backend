package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrNoMatches returned when search has no results
var ErrNoMatches = errors.New("sql: no matching search results")

// SearchRow structure
type SearchRow struct {
	Kind   string
	KindID int
	Fields [3]string
}

// RankedRow structure
type RankedRow struct {
	Kind    string
	KindID  int
	Matches int
}

func searchDB(term string, subName string, username string) ([]RankedRow, error) {
	query := fmt.Sprintf("SELECT id, thread_title, thread_body, thread_link FROM threads WHERE (thread_title LIKE '%%%s%%' OR thread_body LIKE '%%%s%%' or thread_link LIKE '%%%s%%')", term, term, term)
	if subName != "" {
		subID, _ := getIDFromSubName(subName)
		query += fmt.Sprintf("AND sub_id=%d", subID)
	}
	if username != "" {
		userID, _ := getIDFromUsername(username)
		query += fmt.Sprintf(" AND created_by=%d", userID)
	}
	rows, err := database.Query(query)
	if err != nil {
		return nil, err
	}
	var searchRows []SearchRow
	defer rows.Close()
	for rows.Next() {
		var s SearchRow
		s.Kind = "thread"
		rows.Scan(&s.KindID, &s.Fields[0], &s.Fields[1], &s.Fields[2])
		searchRows = append(searchRows, s)
	}
	query = fmt.Sprintf("SELECT id, body FROM comments WHERE body LIKE '%%%s%%'", term)
	if subName != "" {
		subID, _ := getIDFromSubName(subName)
		query += fmt.Sprintf("AND sub_id=%d", subID)
	}
	if username != "" {
		userID, _ := getIDFromUsername(username)
		query += fmt.Sprintf(" AND created_by=%d", userID)
	}
	rows, err = database.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s SearchRow
		s.Kind = "comment"
		rows.Scan(&s.KindID, &s.Fields[0])
		searchRows = append(searchRows, s)
	}
	if len(searchRows) == 0 {
		return nil, ErrNoMatches
	}
	var rankedRows []RankedRow
	for i := range searchRows {
		r := RankedRow{Kind: searchRows[i].Kind, KindID: searchRows[i].KindID}
		var counter int
		for j := range searchRows[i].Fields {
			counter += strings.Count(searchRows[i].Fields[j], term)
		}
		r.Matches = counter
		rankedRows = append(rankedRows, r)
	}
	sort.Slice(rankedRows, func(i, j int) bool {
		return rankedRows[i].Matches > rankedRows[j].Matches
	})
	if len(rankedRows) > 10 {
		rankedRows = rankedRows[:10]
	}
	return rankedRows, err
}

func getDataForSearchResults(results []RankedRow) ([]interface{}, error) {
	var err error
	var data []interface{}
	for i := range results {
		if results[i].Kind == "thread" {
			var (
				listing     = Thread{Kind: "thread"}
				subID       int
				createdByID int
				ID          int
				imageID     int
			)
			err := database.QueryRow("SELECT sub_id, created_by, thread_type, thread_title, thread_link, image_id, created_on FROM threads WHERE id=?", results[i].KindID).Scan(&subID, &createdByID, &listing.ThreadType, &listing.ThreadTitle, &listing.ThreadLink, &imageID, &listing.CreatedOn)
			if err != nil {
				return data, err
			}
			listing.SubName, err = getSubNameFromID(subID)
			listing.CreatedBy, err = getUsernameFromID(createdByID)
			listing.ID = base10to36(ID)
			listing.CommentCount, err = getCommentCount(ID)
			if imageID != 0 {
				listing.ImageURL, err = getURLFromImageID(imageID)
			}
			if err != nil {
				return data, err
			}
			listing.Points, _ = countPoints("thread", ID)
			listing.ThreadURL = titleToURL(listing.ThreadTitle)
			listing.ID = base10to36(results[i].KindID)
			data = append(data, listing)
		}
		if results[i].Kind == "comment" {
			var (
				comment  = Comment{Kind: "comment"}
				userID   int
				threadID int
				subID    int
				parentID int
			)
			err := database.QueryRow("SELECT body, created_by, thread_id, sub_id, parent_id, created_on FROM comments WHERE id=?", results[i].KindID).Scan(&comment.Body, &userID, &threadID, &subID, &parentID, &comment.CreatedOn)
			comment.ID = base10to36(results[i].KindID)
			comment.Username, err = getUsernameFromID(userID)
			comment.ThreadID = base10to36(threadID)
			comment.SubName, err = getSubNameFromID(subID)
			comment.ParentID = base10to36(parentID)
			comment.Points, err = countPoints("comment", results[i].KindID)
			if err != nil {
				return data, err
			}
			data = append(data, comment)
		}
	}
	return data, err
}
