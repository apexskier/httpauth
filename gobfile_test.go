package httpauth

import (
    "testing"
    "os"
    "bytes"
)

func init() {
    os.Remove(file)
    b = NewGobFileAuthBackend(file)
}

func TestNewGobFileAuthBackend(t *testing.T) {
    if b.filepath != file {
        t.Fatal("File path not saved.")
    }
    if len(b.users) != 0 {
        t.Fatal("Users initialized with items.")
    }
}

func TestSaveUser(t *testing.T) {
    user := UserData{"username", "email", []byte("passwordhash")}
    b.SaveUser(user)

    user2 := UserData{"username2", "email2", []byte("passwordhash2")}
    b.SaveUser(user2)

    if len(b.users) != 2 {
        t.Fatal("Users not added properly.")
    }
    if b.users["username"].Username != "username" {
        t.Fatal("Username not correct.")
    }
    if b.users["username"].Email != "email" {
        t.Fatal("User email not correct.")
    }
    if !bytes.Equal(b.users["username"].Hash, []byte("passwordhash")) {
        t.Fatal("User password not correct.")
    }
    if b.users["username2"].Username != "username2" {
        t.Fatal("Username not correct.")
    }
    if b.users["username2"].Email != "email2" {
        t.Fatal("User email not correct.")
    }
    if !bytes.Equal(b.users["username2"].Hash, []byte("passwordhash2")) {
        t.Fatal("User password not correct.")
    }
}

func TestNewGobFileAuthBackend_existing(t *testing.T) {
    b2 := NewGobFileAuthBackend(file)

    if len(b2.users) != 2 {
        t.Fatal("Users not loaded.")
    }
    if b2.users["username"].Username != "username" {
        t.Fatal("Username not correct.")
    }
    if b2.users["username"].Email != "email" {
        t.Fatal("User email not correct.")
    }
    if !bytes.Equal(b2.users["username"].Hash, []byte("passwordhash")) {
        t.Fatal("User password not correct.")
    }
    if b2.users["username2"].Username != "username2" {
        t.Fatal("Username not correct.")
    }
    if b2.users["username2"].Email != "email2" {
        t.Fatal("User email not correct.")
    }
    if !bytes.Equal(b2.users["username2"].Hash, []byte("passwordhash2")) {
        t.Fatal("User password not correct.")
    }
}

func TestUser_existing(t *testing.T) {
    if user, ok := b.User("username"); ok {
        if user.Username != "username" {
            t.Fatal("Username not correct.")
        }
        if user.Email != "email" {
            t.Fatal("User email not correct.")
        }
        if !bytes.Equal(user.Hash, []byte("passwordhash")) {
            t.Fatal("User password not correct.")
        }
    } else {
        t.Fatal("User not found")
    }
}

func TestUser_notexisting(t *testing.T) {
    if _, ok := b.User("notexist"); ok {
        t.Fatal("Not existing user found.")
    }
}

func TestUsers(t *testing.T) {
    var (
        u1 UserData
        u2 UserData
    )
    users := b.Users()
    if len(users) != 2 {
        t.Fatal("Wrong amount of users found.")
    }
    if users[0].Username == "username" {
        u1 = users[0]
        u2 = users[1]
    } else if users[1].Username == "username" {
        u1 = users[1]
        u2 = users[0]
    } else {
        t.Fatal("One of the users not found.")
    }

    if u1.Username != "username" {
        t.Fatal("Username not correct.")
    }
    if u1.Email != "email" {
        t.Fatal("User email not correct.")
    }
    if !bytes.Equal(u1.Hash, []byte("passwordhash")) {
        t.Fatal("User password not correct.")
    }
    if u2.Username != "username2" {
        t.Fatal("Username not correct.")
    }
    if u2.Email != "email2" {
        t.Fatal("User email not correct.")
    }
    if !bytes.Equal(u2.Hash, []byte("passwordhash2")) {
        t.Fatal("User password not correct.")
    }
}

func TestUpdateUser_gob(t *testing.T) {
    user2 := UserData{"username", "email", []byte("newpassword")}
    if err := b.SaveUser(user2); err != nil {
        t.Fatalf("SaveUser gob error: %v", err)
    }
    u2, ok := b.User("username")
    if !ok {
        t.Fatal("Updated user not found")
    }
    if u2.Username != "username" {
        t.Fatal("Username not correct.")
    }
    if u2.Email != "email" {
        t.Fatal("User email not correct.")
    }
    if !bytes.Equal(u2.Hash, []byte("newpassword")) {
        t.Fatal("User password not correct.")
    }
}

func TestGobDeleteUser(t *testing.T) {
    if err := b.DeleteUser("username"); err != nil {
        t.Fatalf("DeleteUser error: %v", err)
    }
    if _, ok := b.User("username"); ok {
        t.Fatalf("DeleteUser: User not deleted")
    }
    if err := b.DeleteUser("username"); err != nil {
        t.Fatalf("DeleteUser error: %v", err)
    }
}
