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
