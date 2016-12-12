package httpauth

import (
	"encoding/json"
	"os"
	"testing"
	"fmt"
)

var (
	filedb = "test.json"
)

func TestInitFileAuthBackend(t *testing.T) {
	os.Remove(filedb)
	b, err := NewFileAuthBackend(filedb)
	if err != ErrMissingFileBackend {
		t.Fatal(err.Error())
	}
	// Create test file
	file, err := os.OpenFile(filedb,os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	users:= map[string]UserData{}
	data, err := json.Marshal(users)
	if err != nil {
		fmt.Println(err)
	}
	file.Write(data)
	file.Close()
	//
	b, err = NewFileAuthBackend(filedb)
	if err != nil {
		t.Fatal(err.Error())
	}
	if b.filepath != filedb {
		t.Fatal("File path not saved.")
	}
	if len(b.users) != 0 {
		t.Fatal("Users initialized with items.")
	}

	testBackend(t, b)
}

func TestFileReopen(t *testing.T) {
	b, err := NewFileAuthBackend(filedb)
	if err != nil {
		t.Fatal(err.Error())
	}
	b.Close()
	b, err = NewFileAuthBackend(filedb)
	if err != nil {
		t.Fatal(err.Error())
	}

	testBackend2(t, b)
}