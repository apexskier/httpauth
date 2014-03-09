package goauth

import (
    "testing"
    //"os"
    //"database/sql"
    "bytes"
    _ "github.com/ziutek/mymysql/godrv"
)

var sb SqlAuthBackend

func init() {

}

func TestNewSqlAuthBackend(t *testing.T) {
    sb = NewSqlAuthBackend("mymysql", "test/testuser/TestPasswd9")
    if sb.driverName != "mymysql" {
        t.Fatal("Driver name.")
    }
    if sb.dataSourceName != "test/testuser/TestPasswd9" {
        t.Fatal("Driver info not saved.")
    }
}

func TestSaveUser_sql(t *testing.T) {
    user := UserData{"username", "email", []byte("passwordhash")}
    if err := sb.SaveUser(user); err != nil {
        t.Fatalf("SaveUser sql error: %v", err)
    }

    user2 := UserData{"username2", "email2", []byte("passwordhash2")}
    if err := sb.SaveUser(user2); err != nil {
        t.Fatalf("SaveUser sql error: %v", err)
    }
}

/*
func TestNewSqlAuthBackend_existing(t *testing.T) {
    b2 := NewSqlAuthBackend(file)

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
*/

func TestUser_existing_sql(t *testing.T) {
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

func TestUser_notexisting_sql(t *testing.T) {
    if _, ok := b.User("notexist"); ok {
        t.Fatal("Not existing user found.")
    }
}

func TestUser_sql(t *testing.T) {
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

func TestSqlDeleteUser_sql(t *testing.T) {
    if err := b.DeleteUser("username"); err != nil {
        t.Fatalf("DeleteUser error: %v", err)
    }
    if err := b.DeleteUser("username"); err != nil {
        t.Fatalf("DeleteUser error: %v", err)
    }
}
