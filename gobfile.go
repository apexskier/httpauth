package httpauth

import (
	"encoding/gob"
	"errors"
	"fmt"
	"os"
)

// ErrMissingBackend is returned by NewGobFileAuthBackend when the file doesn't
// exist. Be sure to create (or touch) it if using brand new backend or
// resetting backend.
var (
	ErrMissingBackend = errors.New("gobfilebackend: missing backend")
)

// GobFileAuthBackend stores user data and the location of the gob file.
type GobFileAuthBackend struct {
	filepath string
	users    map[string]UserData
}

// NewGobFileAuthBackend initializes a new backend by loading a map of users
// from a file.
// If the file doesn't exist, returns an error.
func NewGobFileAuthBackend(filepath string) (b GobFileAuthBackend, e error) {
	b.filepath = filepath
	if _, err := os.Stat(b.filepath); err == nil {
		f, err := os.Open(b.filepath)
		defer f.Close()
		if err != nil {
			return b, fmt.Errorf("gobfilebackend: %v", err.Error())
		}
		dec := gob.NewDecoder(f)
		dec.Decode(&b.users)
	} else if !os.IsNotExist(err) {
		return b, fmt.Errorf("gobfilebackend: %v", err.Error())
	} else {
		return b, ErrMissingBackend
	}
	if b.users == nil {
		b.users = make(map[string]UserData)
	}
	return b, nil
}

// User returns the user with the given username. Error is set to
// ErrMissingUser if user is not found.
func (b GobFileAuthBackend) User(username string) (user UserData, e error) {
	if user, ok := b.users[username]; ok {
		return user, nil
	}
	return user, ErrMissingUser
}

// Users returns a slice of all users.
func (b GobFileAuthBackend) Users() (us []UserData, e error) {
	for _, user := range b.users {
		us = append(us, user)
	}
	return
}

// SaveUser adds a new user, replacing one with the same username, and saves a
// gob file.
func (b GobFileAuthBackend) SaveUser(user UserData) error {
	b.users[user.Username] = user
	err := b.save()
	return err
}

func (b GobFileAuthBackend) save() error {
	f, err := os.Create(b.filepath)
	defer f.Close()
	if err != nil {
		return errors.New("gobfilebackend: failed to edit auth file")
	}
	enc := gob.NewEncoder(f)
	err = enc.Encode(b.users)
	if err != nil {
		fmt.Errorf("gobfilebackend: save: %v", err)
	}
	return nil
}

// DeleteUser removes a user, raising ErrDeleteNull if that user was missing.
func (b GobFileAuthBackend) DeleteUser(username string) error {
	_, err := b.User(username)
	if err == ErrMissingUser {
		return ErrDeleteNull
	} else if err != nil {
		return fmt.Errorf("gobfilebackend: %v", err)
	}
	delete(b.users, username)
	return b.save()
}

// Close cleans up the backend. Currently a no-op for gobfiles.
func (b GobFileAuthBackend) Close() {

}
