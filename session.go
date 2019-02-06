package main

import (
	"net/http"

	"github.com/satori/go.uuid"
)

func getUser(w http.ResponseWriter, req *http.Request) user {
	// get cookie
	c, err := req.Cookie("session")
	if err != nil {
		sID, _ := uuid.NewV4()
		c = &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
	}

	http.SetCookie(w, c)

	// if the user exists already, get user
	var u user
	if un, ok := dbSessions[c.Value]; ok {
		u = dbUsers[un]
	}
	return u
}

// checks if the user is already logged in
func alreadyLoggedIn(req *http.Request) bool {
	// grabs the sessnio cookie
	c, err := req.Cookie("session")
	//  if there is no cookie return false
	if err != nil {
		return false
	}

	// finds the user based on the session cookie
	un := dbSessions[c.Value]
	_, ok := dbUsers[un]
	// returns true if the user is found
	return ok
}
