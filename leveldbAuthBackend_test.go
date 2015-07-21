package httpauth

import (
	"os"
	"testing"
)

var (
	fileldb = "test.ldb"
)

func TestInitLeveldbAuthBackend(t *testing.T) {
	// test if ErrMissingLeveldbBackend is thrown if no leveldb database exists
	os.Remove(fileldb)
	b, err := NewLeveldbAuthBackend(fileldb)
	if err != ErrMissingLeveldbBackend {
		t.Fatal(err.Error())
	}

	os.Mkdir(fileldb, 0700)
	defer os.Remove(fileldb)
	b, err = NewLeveldbAuthBackend(fileldb)
	if err != nil {
		t.Fatal(err.Error())
	}
	if b.filepath != fileldb {
		t.Fatal("File path not saved.")
	}
	if len(b.users) != 0 {
		t.Fatal("Users initialized with items.")
	}

	testBackend(t, b)
}

func TestLeveldbReopen(t *testing.T) {
	b, err := NewLeveldbAuthBackend(fileldb)
	if err != nil {
		t.Fatal(err.Error())
	}
	b.Close()
	b, err = NewLeveldbAuthBackend(fileldb)
	if err != nil {
		t.Fatal(err.Error())
	}

	testBackend2(t, b)
}
