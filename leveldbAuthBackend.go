package httpauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/syndtr/goleveldb/leveldb"
	"os"
)

// ErrMissingLeveldbBackend is returned by NewLeveldbAuthBackend when the file
// doesn't exist. Be sure to create (or touch) it if using brand new backend or
// resetting backend.
var (
	ErrMissingLeveldbBackend = errors.New("leveldbauthbackend: missing backend")
)

// LeveldbAuthBackend stores user data and the location of a leveldb file.
//
// Current implementation holds all user data in memory, flushing to leveldb
// as a single value to the key "httpauth::userdata" on saves.
type LeveldbAuthBackend struct {
	filepath string
	users    map[string]UserData
}

// NewLeveldbAuthBackend initializes a new backend by loading a map of users
// from a file.
// If the file doesn't exist, returns an error.
func NewLeveldbAuthBackend(filepath string) (b LeveldbAuthBackend, e error) {
	b.filepath = filepath
	if _, err := os.Stat(b.filepath); err == nil {
		db, err := leveldb.OpenFile(b.filepath, nil)
		defer db.Close()
		if err != nil {
			return b, fmt.Errorf("leveldbauthbackend: %v", err.Error())
		}
		data, err := db.Get([]byte("httpauth::userdata"), nil)
		err = json.Unmarshal(data, &b.users)
		if err != nil {
			b.users = make(map[string]UserData)
		}
	} else {
		return b, ErrMissingLeveldbBackend
	}
	if b.users == nil {
		b.users = make(map[string]UserData)
	}
	return b, nil
}

// User returns the user with the given username. Error is set to
// ErrMissingUser if user is not found.
func (b LeveldbAuthBackend) User(username string) (user UserData, e error) {
	if user, ok := b.users[username]; ok {
		return user, nil
	}
	return user, ErrMissingUser
}

// Users returns a slice of all users.
func (b LeveldbAuthBackend) Users() (us []UserData, e error) {
	for _, user := range b.users {
		us = append(us, user)
	}
	return
}

// SaveUser adds a new user, replacing one with the same username, and flushes
// to the db.
func (b LeveldbAuthBackend) SaveUser(user UserData) error {
	b.users[user.Username] = user
	err := b.save()
	return err
}

func (b LeveldbAuthBackend) save() error {
	db, err := leveldb.OpenFile(b.filepath, nil)
	defer db.Close()
	if err != nil {
		return errors.New("leveldbauthbackend: failed to edit auth file")
	}
	data, err := json.Marshal(b.users)
	if err != nil {
		return errors.New(fmt.Sprintf("leveldbauthbackend: save: %v", err))
	}
	err = db.Put([]byte("httpauth::userdata"), data, nil)
	if err != nil {
		return errors.New(fmt.Sprintf("leveldbauthbackend: save: %v", err))
	}
	return nil
}

// DeleteUser removes a user, raising ErrDeleteNull if that user was missing.
func (b LeveldbAuthBackend) DeleteUser(username string) error {
	_, err := b.User(username)
	if err == ErrMissingUser {
		return ErrDeleteNull
	} else if err != nil {
		return fmt.Errorf("leveldbauthbackend: %v", err)
	}
	delete(b.users, username)
	return b.save()
}

// Close cleans up the backend. Currently a no-op for gobfiles.
func (b LeveldbAuthBackend) Close() {

}
