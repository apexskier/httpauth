package httpauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

var (
	ErrMissingFileBackend = errors.New("fileauthbackend: missing backend")
)

type FileAuthBackend struct {
	filepath string
	users    map[string]UserData
}

func NewFileAuthBackend(filepath string) (b FileAuthBackend, e error) {
	b.filepath = filepath
	if _, err := os.Stat(b.filepath); err == nil {
		file, err := os.Open(b.filepath)
		defer file.Close()
		if err != nil {
			return b, fmt.Errorf("fileauthbackend: %v", err.Error())
		}
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&b.users)
		if err != nil {
			b.users = make(map[string]UserData)
		}
	} else {
		return b, ErrMissingFileBackend
	}
	if b.users == nil {
		b.users = make(map[string]UserData)
	}
	return b, nil
}

func (b FileAuthBackend) User(username string) (user UserData, e error) {
	if user, ok := b.users[username]; ok {
		return user, nil
	}
	return user, ErrMissingUser
}

func (b FileAuthBackend) Users() (us []UserData, e error) {
	for _, user := range b.users {
		us = append(us, user)
	}
	return
}

func (b FileAuthBackend) SaveUser(user UserData) error {
	b.users[user.Username] = user
	err := b.save()
	return err
}

func (b FileAuthBackend) save() error {
	file, err := os.OpenFile(b.filepath,os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	defer file.Close()
	if err != nil {
		fmt.Printf("==>%v",err)
		return errors.New("fileauthbackend: failed to edit auth file")
	}
	data, err := json.Marshal(b.users)
	if err != nil {
		return errors.New(fmt.Sprintf("fileauthbackend: save: %v", err))
	}
	_,err = file.Write(data)
	if err != nil {
		return errors.New(fmt.Sprintf("fileauthbackend: save: %v", err))
	}
	return nil
}

func (b FileAuthBackend) DeleteUser(username string) error {
	_, err := b.User(username)
	if err == ErrMissingUser {
		return ErrDeleteNull
	} else if err != nil {
		return fmt.Errorf("filebauthbackend: %v", err)
	}
	delete(b.users, username)
	return b.save()
}

func (b FileAuthBackend) Close() {

}
