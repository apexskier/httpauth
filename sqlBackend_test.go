package httpauth

import (
    "testing"
    "os"
    "bytes"
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
)

var (
    sb SqlAuthBackend
    driverName string = "mysql"
    driverInfo string = "testuser:TestPasswd9@tcp(localhost:3306)/test"
)

func TestSqlInit(t *testing.T) {
    con, err := sql.Open(driverName, driverInfo)
    if err != nil {
        t.Fatalf("Couldn't set up test database: %v", err)
        os.Exit(1)
    }
    con.Exec("drop table goauth")
}

func TestNewSqlAuthBackend(t *testing.T) {
    sb = NewSqlAuthBackend(driverName, driverInfo)
    if sb.driverName != driverName {
        t.Fatal("Driver name.")
    }
    if sb.dataSourceName != driverInfo {
        t.Fatal("Driver info not saved.")
    }
}

func TestSaveUser_sql(t *testing.T) {
    user2 := UserData{"username2", "email2", []byte("passwordhash2")}
    if err := sb.SaveUser(user2); err != nil {
        t.Fatalf("SaveUser sql error: %v", err)
    }

    user := UserData{"username", "email", []byte("passwordhash")}
    if err := sb.SaveUser(user); err != nil {
        t.Fatalf("SaveUser sql error: %v", err)
    }
}

func TestNewSqlAuthBackend_existing(t *testing.T) {
    b2 := NewSqlAuthBackend(driverName, driverInfo)

    user, ok := b2.User("username")
    if !ok {
        t.Fatal("Secondary backend failed")
    }
    if user.Username != "username" {
        t.Fatal("Username not correct.")
    }
    if user.Email != "email" {
        t.Fatal("User email not correct.")
    }
    if !bytes.Equal(user.Hash, []byte("passwordhash")) {
        t.Fatal("User password not correct.")
    }
}

func TestUser_existing_sql(t *testing.T) {
    if user, ok := sb.User("username"); ok {
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
    if user, ok := sb.User("username2"); ok {
        if user.Username != "username2" {
            t.Fatal("Username not correct.")
        }
        if user.Email != "email2" {
            t.Fatal("User email not correct.")
        }
        if !bytes.Equal(user.Hash, []byte("passwordhash2")) {
            t.Fatal("User password not correct.")
        }
    } else {
        t.Fatal("User not found")
    }
}

func TestUser_notexisting_sql(t *testing.T) {
    if _, ok := sb.User("notexist"); ok {
        t.Fatal("Not existing user found.")
    }
}

func TestUsers_sql(t *testing.T) {
    var (
        u1 UserData
        u2 UserData
    )
    users := sb.Users()
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

func TestUpdateUser_sql(t *testing.T) {
    user2 := UserData{"username", "email", []byte("newpassword")}
    if err := sb.SaveUser(user2); err != nil {
        t.Fatalf("SaveUser sql error: %v", err)
    }
    u2, ok := sb.User("username")
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

func TestSqlDeleteUser_sql(t *testing.T) {
    if err := sb.DeleteUser("username"); err != nil {
        t.Fatalf("DeleteUser error: %v", err)
    }
    if err := sb.DeleteUser("username"); err != nil {
        t.Fatalf("DeleteUser error: %v", err)
    }

    if err := sb.DeleteUser("username2"); err != nil {
        t.Fatalf("DeleteUser error: %v", err)
    }
}
