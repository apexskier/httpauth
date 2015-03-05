package httpauth

import (
	"fmt"
	"gopkg.in/mgo.v2"
	"os"
	"testing"
)

func TestMongodbInit(t *testing.T) {
	con, err := mgo.Dial("mongodb://127.0.0.1/")
	if err != nil {
		fmt.Printf("Couldn't set up test mongodb session: %v\n", err)
		os.Exit(1)
	}
	defer con.Close()
	err = con.Ping()
	if err != nil {
		t.Errorf("Couldn't ping test mongodb database: %v", err)
		fmt.Printf("Couldn't ping test mongodb database: %v\n", err)
		// t.Errorf("Couldn't ping test database: %v\n", err)
		os.Exit(1)
	}
	database := con.DB("httpauth_test")
	err = database.DropDatabase()
	if err != nil {
		t.Errorf("Couldn't drop test mongodb database: %v", err)
		fmt.Printf("Couldn't drop test mongodb database: %v\n", err)
		// t.Errorf("Couldn't ping test database: %v\n", err)
		os.Exit(1)
	}
}

func TestNewMongodbAuthBackend(t *testing.T) {
	// Note: the following takes 10 seconds. It really should be included, but
	// I don't want to wait that long.
	//_, err = NewMongodbBackend("mongodb://example.com.doesntexist", db)
	//if err == nil {
	//    t.Fatal("Expected error on invalid url.")
	//}
	mongo_backend, err := NewMongodbBackend("mongodb://doesn'texist/", "httpauth_test")
	if err == nil {
		t.Fatalf("expected NewMongodbBackend error")
	}
	mongo_backend, err = NewMongodbBackend("mongodb://127.0.0.1/", "httpauth_test")
	if err != nil {
		t.Fatalf("NewMongodbBackend error: %v", err)
	}
	if mongo_backend.mongoURL != "mongodb://127.0.0.1/" {
		t.Error("Url name.")
	}
	if mongo_backend.database != "httpauth_test" {
		t.Error("DB not saved.")
	}

	testBackend(t, mongo_backend)
}

func TestMongodbReopen(t *testing.T) {
	mongo_backend, err := NewMongodbBackend("mongodb://127.0.0.1/", "httpauth_test")
	if err != nil {
		t.Fatal(err.Error())
	}
	mongo_backend.Close()
	mongo_backend, err = NewMongodbBackend("mongodb://127.0.0.1/", "httpauth_test")
	if err != nil {
		t.Fatal(err.Error())
	}

	testBackend2(t, mongo_backend)
}
