package httpauth

import (
    "bytes"
    "testing"
    "os"
)

func TestNewGobFileAuthBackend(t *testing.T) {
    var err error

    os.Remove(file)
    b, err = NewGobFileAuthBackend(file)
    if err != ErrMissingBackend {
        t.Fatal(err.Error())
    }

    _, err = os.Create(file)
    if err != nil {
        t.Fatal(err.Error())
    }
    b, err = NewGobFileAuthBackend(file)
    if err != nil {
        t.Fatal(err.Error())
    }
    if b.filepath != file {
        t.Fatal("File path not saved.")
    }
    if len(b.users) != 0 {
        t.Fatal("Users initialized with items.")
    }
}

func TestGobFileAuthorizer(t *testing.T) {
    roles := make(map[string]Role)
    roles["user"] = 40
    roles["admin"] = 80
    _, err := NewAuthorizer(b, []byte("testkey"), "user", roles)
    if err != nil {
        t.Fatal(err)
    }
}

func TestSaveUser(t *testing.T) {
    user := UserData{Username:"username", Email:"email", Hash:[]byte("passwordhash"), Role:"user"}
    b.SaveUser(user)

    user2 := UserData{Username:"username2", Email:"email2", Hash:[]byte("passwordhash2"), Role:"user"}
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
    if b.users["username"].Role != "user" {
        t.Fatal("User role not correct.")
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
    b2, err := NewGobFileAuthBackend(file)
    if err != nil {
        t.Fatal(err.Error())
    }

    if len(b2.users) != 2 {
        t.Error("Users not loaded.")
    }
    if b2.users["username"].Username != "username" {
        t.Error("Username not correct.")
    }
    if b2.users["username"].Email != "email" {
        t.Error("User email not correct.")
    }
    if !bytes.Equal(b2.users["username"].Hash, []byte("passwordhash")) {
        t.Error("User password not correct.")
    }
    if b2.users["username2"].Username != "username2" {
        t.Error("Username not correct.")
    }
    if b2.users["username2"].Email != "email2" {
        t.Error("User email not correct.")
    }
    if !bytes.Equal(b2.users["username2"].Hash, []byte("passwordhash2")) {
        t.Error("User password not correct.")
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
        if user.Role != "user" {
            t.Fatal("user role not correct")
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
    users, err := b.Users()
    if err != nil {
        t.Fatal(err.Error())
    }
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
    if u1.Role != "user" {
        t.Fatal("User role not correct")
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
    user2 := UserData{Username:"username", Email:"email", Hash:[]byte("newpassword"), Role:"newrole"}
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
    if u2.Role != "newrole" {
        t.Fatal("user role not correct")
    }
    if !bytes.Equal(u2.Hash, []byte("newpassword")) {
        t.Fatalf("User password not correct. Got %v, expected %v", u2.Hash, []byte("newpassword"))
    }
}

func TestGobDeleteUser(t *testing.T) {
    if err := b.DeleteUser("username"); err != nil {
        t.Fatalf("DeleteUser error: %v", err)
    }
    if _, ok := b.User("username"); ok {
        t.Fatal("DeleteUser: User not deleted")
    }
    err := b.DeleteUser("username")
    if err != ErrDeleteNull {
        t.Fatalf("DeleteUser should have raised ErrDeleteNull: %v", err)
    } else if err != ErrDeleteNull {
        t.Fatalf("DeleteUser raised unexpected error: %v", err)
    }
}

func TestGobReopen(t *testing.T) {
    b.Close()
    b, err := NewGobFileAuthBackend(file)
    if err != nil {
        t.Fatal(err.Error())
    }
    b.Close()

    b, err = NewGobFileAuthBackend(file)
    if err != nil {
        t.Fatal(err.Error())
    }

    if len(b.users) != 1 {
        t.Error("Users not loaded.")
    }
    if b.users["username2"].Username != "username2" {
        t.Error("Username not correct.")
    }
    if b.users["username2"].Email != "email2" {
        t.Error("User email not correct.")
    }
    if !bytes.Equal(b.users["username2"].Hash, []byte("passwordhash2")) {
        t.Error("User password not correct.")
    }
}

func TestGobReclose(t *testing.T) {
    b.Close()
    err := os.Remove(file)
    if err != nil {
        t.Fatal(err.Error())
    }
}
