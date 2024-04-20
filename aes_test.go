package aesbuddy_test

import (
	"slices"
	"testing"

	"github.com/aixoio/aesbuddy"
)

func TestAesGCM128(t *testing.T) {
	key := []byte("THIS IS MY KEY!!")
	data := []byte("MY SECRET MESSAGE")

	enced, err := aesbuddy.AesGCMEncrpyt(key, data)
	if err != nil {
		t.Fatalf(err.Error())
		t.Fail()
		return
	}

	deced, err := aesbuddy.AesGCMDecrpyt(key, enced)
	if err != nil {
		t.Fatalf(err.Error())
		t.Fail()
		return
	}

	if slices.Compare(deced, enced) == 0 {
		t.Log("enced == deced")
		t.Fail()
		return
	}

	if slices.Compare(data, deced) != 0 {
		t.Log("data != deced")
		t.Fail()
		return
	}

}
