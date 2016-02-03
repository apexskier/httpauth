package httpauth

import (
	"os"
	"testing"
)

// Establish new gobfile for testing due to issues with busy process from previous test.
var gobfile = "gobfile_test.gob"

func TestInitGobFileAuthBackend(t *testing.T) {
	err := os.Remove(gobfile)
	b, err := NewGobFileAuthBackend(gobfile)
	if err != ErrMissingBackend {
		t.Fatal(err.Error())
	}

	_, err = os.Create(gobfile)
	if err != nil {
		t.Fatal(err.Error())
	}
	b, err = NewGobFileAuthBackend(gobfile)
	if err != nil {
		t.Fatal(err.Error())
	}
	if b.filepath != gobfile {
		t.Fatal("File path not saved.")
	}
	if len(b.users) != 0 {
		t.Fatal("Users initialized with items.")
	}

	testBackend(t, b)
}

func TestGobReopen(t *testing.T) {
	b, err := NewGobFileAuthBackend(gobfile)
	if err != nil {
		t.Fatal(err.Error())
	}
	b.Close()
	b, err = NewGobFileAuthBackend(gobfile)
	if err != nil {
		t.Fatal(err.Error())
	}

	testBackend2(t, b)
}
