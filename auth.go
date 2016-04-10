// Package httpauth implements cookie/session based authentication and
// authorization. Intended for use with the net/http or github.com/gorilla/mux
// packages, but may work with github.com/codegangsta/martini as well.
// Credentials are stored as a username + password hash, computed with bcrypt.
//
// Three user storage systems are currently implemented: file based
// (encoding/gob), sql databases (database/sql), and MongoDB databases.
//
// Access can be restricted by a users' role. A higher role will give more
// access.
//
// Users can be redirected to the page that triggered an authentication error.
//
// Messages describing the reason a user could not authenticate are saved in a
// cookie, and can be accessed with the Messages function.
//
// Example source can be found at
// https://github.com/apexskier/httpauth/blob/master/examples/server.go
package httpauth

import (
	"errors"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

// ErrDeleteNull is returned by DeleteUser when that user didn't exist at the
// time of call.
// ErrMissingUser is returned by Users when a user is not found.
var (
	ErrDeleteNull  = mkerror("deleting non-existant user")
	ErrMissingUser = mkerror("can't find user")
)

// Role represents an interal role. Roles are essentially a string mapped to an
// integer. Roles must be greater than zero.
type Role int

// UserData represents a single user. It contains the users username, email,
// and role as well as a hash of their password. When creating
// users, you should not specify a hash; it will be generated in the Register
// and Update functions.
type UserData struct {
	Username string `bson:"Username"`
	Email    string `bson:"Email"`
	Hash     []byte `bson:"Hash"`
	Role     string `bson:"Role"`
}

// Authorizer structures contain the store of user session cookies a reference
// to a backend storage system.
type Authorizer struct {
	cookiejar   *sessions.CookieStore
	backend     AuthBackend
	defaultRole string
	roles       map[string]Role
}

// The AuthBackend interface defines a set of methods an AuthBackend must
// implement.
type AuthBackend interface {
	SaveUser(u UserData) error
	User(username string) (user UserData, e error)
	Users() (users []UserData, e error)
	DeleteUser(username string) error
	Close()
}

// Helper function to add a user directed message to a message queue.
func (a Authorizer) addMessage(rw http.ResponseWriter, req *http.Request, message string) {
	messageSession, _ := a.cookiejar.Get(req, "messages")
	defer messageSession.Save(req, rw)
	messageSession.AddFlash(message)
}

// Helper function to save a redirect to the page a user tried to visit before
// logging in.
func (a Authorizer) goBack(rw http.ResponseWriter, req *http.Request) {
	redirectSession, _ := a.cookiejar.Get(req, "redirects")
	defer redirectSession.Save(req, rw)
	redirectSession.Flashes()
	redirectSession.AddFlash(req.URL.Path)
}

func mkerror(msg string) error {
	return errors.New("httpauth: " + msg)
}

// NewAuthorizer returns a new Authorizer given an AuthBackend, a cookie store
// key, a default user role, and a map of roles. If the key changes, logged in
// users will need to reauthenticate.
//
// Roles are a map of string to httpauth.Role values (integers). Higher Role values
// have more access.
//
// Example roles:
//
//     var roles map[string]httpauth.Role
//     roles["user"] = 2
//     roles["admin"] = 4
//     roles["moderator"] = 3
func NewAuthorizer(backend AuthBackend, key []byte, defaultRole string, roles map[string]Role) (Authorizer, error) {
	var a Authorizer
	a.cookiejar = sessions.NewCookieStore([]byte(key))
	a.backend = backend
	a.roles = roles
	a.defaultRole = defaultRole
	if _, ok := roles[defaultRole]; !ok {
		return a, mkerror("httpauth: defaultRole missing")
	}
	return a, nil
}

// Login logs a user in. They will be redirected to dest or to the last
// location an authorization redirect was triggered (if found) on success. A
// message will be added to the session on failure with the reason.
func (a Authorizer) Login(rw http.ResponseWriter, req *http.Request, u string, p string, dest string) error {
	session, _ := a.cookiejar.Get(req, "auth")
	if session.Values["username"] == u {
		return mkerror("already authenticated")
	}
	if user, err := a.backend.User(u); err == nil {
		verify := bcrypt.CompareHashAndPassword(user.Hash, []byte(p))
		if verify != nil {
			a.addMessage(rw, req, "Invalid username or password.")
			return mkerror("password doesn't match")
		}
	} else {
		a.addMessage(rw, req, "Invalid username or password.")
		return mkerror("user not found")
	}
	session.Values["username"] = u
	session.Save(req, rw)

	redirectSession, _ := a.cookiejar.Get(req, "redirects")
	if flashes := redirectSession.Flashes(); len(flashes) > 0 {
		dest = flashes[0].(string)
	}
	http.Redirect(rw, req, dest, http.StatusSeeOther)
	return nil
}

// Register and save a new user. Returns an error and adds a message if the
// username is in use.
//
// Pass in a instance of UserData with at least a username and email specified. If no role
// is given, the default one is used.
func (a Authorizer) Register(rw http.ResponseWriter, req *http.Request, user UserData, password string) error {
	if user.Username == "" {
		return mkerror("no username given")
	}
	if user.Email == "" {
		return mkerror("no email given")
	}
	if user.Hash != nil {
		return mkerror("hash will be overwritten")
	}
	if password == "" {
		return mkerror("no password given")
	}

	// Validate username
	_, err := a.backend.User(user.Username)
	if err == nil {
		a.addMessage(rw, req, "Username has been taken.")
		return mkerror("user already exists")
	} else if err != ErrMissingUser {
		if err != nil {
			return mkerror(err.Error())
		}
		return nil
	}

	// Generate and save hash
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return mkerror("couldn't save password: " + err.Error())
	}
	user.Hash = hash

	// Validate role
	if user.Role == "" {
		user.Role = a.defaultRole
	} else {
		if _, ok := a.roles[user.Role]; !ok {
			return mkerror("non-existant role")
		}
	}

	err = a.backend.SaveUser(user)
	if err != nil {
		a.addMessage(rw, req, err.Error())
		return mkerror(err.Error())
	}
	return nil
}

// Update changes data for an existing user.
// The behavior of the update varies depending on how the arguments are passed:
//  If an empty username u is passed then it updates the current user from the session
//    (self-edit scenario)
//  If the username u is passed explicitly then it updates the passed username
//    (admin update scenario)
//  If an empty password p is passed then it keeps the original rather than
//    regenerating the hash, if a new password is passed then it regenerates the hash.
//  If an empty email e is passed then it keeps the orginal rather than updating it,
//    if a new email is passedn then it updates it.
func (a Authorizer) Update(rw http.ResponseWriter, req *http.Request, u string, p string, e string) error {
	var (
		hash     []byte
		email    string
		username string
		ok       bool
	)
	if u != "" {
		username = u
	} else {
		authSession, err := a.cookiejar.Get(req, "auth")
		if err != nil {
			return mkerror("couldn't get session needed to update user: " + err.Error())
		}
		username, ok = authSession.Values["username"].(string)
		if !ok {
			return mkerror("not logged in")
		}
	}
	user, err := a.backend.User(username)
	if err == ErrMissingUser {
		a.addMessage(rw, req, "User doesn't exist.")
		return mkerror("user doesn't exists")
	} else if err != nil {
		return mkerror(err.Error())
	}
	if p != "" {
		hash, err = bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
		if err != nil {
			return mkerror("couldn't save password: " + err.Error())
		}
	} else {
		hash = user.Hash
	}
	if e != "" {
		email = e
	} else {
		email = user.Email
	}

	newuser := UserData{username, email, hash, user.Role}

	err = a.backend.SaveUser(newuser)
	if err != nil {
		a.addMessage(rw, req, err.Error())
	}
	return nil
}

// Authorize checks if a user is logged in and returns an error on failed
// authentication. If redirectWithMessage is set, the page being authorized
// will be saved and a "Login to do that." message will be saved to the
// messages list. The next time the user logs in, they will be redirected back
// to the saved page.
func (a Authorizer) Authorize(rw http.ResponseWriter, req *http.Request, redirectWithMessage bool) error {
	authSession, err := a.cookiejar.Get(req, "auth")
	if err != nil {
		if redirectWithMessage {
			a.goBack(rw, req)
		}
		return mkerror("new authorization session")
	}
	/*if authSession.IsNew {
	    if redirectWithMessage {
	        a.goBack(rw, req)
	        a.addMessage(rw, req, "Log in to do that.")
	    }
	    return mkerror("no session existed")
	}*/
	username := authSession.Values["username"]
	if !authSession.IsNew && username != nil {
		_, err := a.backend.User(username.(string))
		if err == ErrMissingUser {
			authSession.Options.MaxAge = -1 // kill the cookie
			authSession.Save(req, rw)
			if redirectWithMessage {
				a.goBack(rw, req)
				a.addMessage(rw, req, "Log in to do that.")
			}
			return mkerror("user not found")
		} else if err != nil {
			return mkerror(err.Error())
		}
	}
	if username == nil {
		if redirectWithMessage {
			a.goBack(rw, req)
			a.addMessage(rw, req, "Log in to do that.")
		}
		return mkerror("user not logged in")
	}
	return nil
}

// AuthorizeRole runs Authorize on a user, then makes sure their role is at
// least as high as the specified one, failing if not.
func (a Authorizer) AuthorizeRole(rw http.ResponseWriter, req *http.Request, role string, redirectWithMessage bool) error {
	r, ok := a.roles[role]
	if !ok {
		return mkerror("role not found")
	}
	if err := a.Authorize(rw, req, redirectWithMessage); err != nil {
		return mkerror(err.Error())
	}
	authSession, _ := a.cookiejar.Get(req, "auth") // should I check err? I've already checked in call to Authorize
	username := authSession.Values["username"]
	if user, err := a.backend.User(username.(string)); err == nil {
		if a.roles[user.Role] >= r {
			return nil
		}
		a.addMessage(rw, req, "You don't have sufficient privileges.")
		return mkerror("user doesn't have high enough role")
	}
	return mkerror("user not found")
}

// CurrentUser returns the currently logged in user and a boolean validating
// the information.
func (a Authorizer) CurrentUser(rw http.ResponseWriter, req *http.Request) (user UserData, e error) {
	if err := a.Authorize(rw, req, false); err != nil {
		return user, mkerror(err.Error())
	}
	authSession, _ := a.cookiejar.Get(req, "auth")

	username, ok := authSession.Values["username"].(string)
	if !ok {
		return user, mkerror("User not found in authsession")
	}
	return a.backend.User(username)
}

// Logout clears an authentication session and add a logged out message.
func (a Authorizer) Logout(rw http.ResponseWriter, req *http.Request) error {
	session, _ := a.cookiejar.Get(req, "auth")
	defer session.Save(req, rw)

	session.Options.MaxAge = -1 // kill the cookie
	a.addMessage(rw, req, "Logged out.")
	return nil
}

// DeleteUser removes a user from the Authorize. ErrMissingUser is returned if
// the user to be deleted isn't found.
func (a Authorizer) DeleteUser(username string) error {
	err := a.backend.DeleteUser(username)
	if err != nil && err != ErrDeleteNull {
		return mkerror(err.Error())
	}
	return err
}

// Messages fetches a list of saved messages. Use this to get a nice message to print to
// the user on a login page or registration page in case something happened
// (username taken, invalid credentials, successful logout, etc).
func (a Authorizer) Messages(rw http.ResponseWriter, req *http.Request) []string {
	session, _ := a.cookiejar.Get(req, "messages")
	flashes := session.Flashes()
	session.Save(req, rw)
	var messages []string
	for _, val := range flashes {
		messages = append(messages, val.(string))
	}
	return messages
}
