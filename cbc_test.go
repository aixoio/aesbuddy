package aesbuddy_test

import (
	"slices"
	"testing"

	"github.com/aixoio/aesbuddy"
)

func TestAesCBC128(t *testing.T) {
	key := []byte("THIS IS MY KEY!!")
	data := []byte("MY SECRET MESSAGE")

	enced, err := aesbuddy.AesCBCEncrpyt(key, data)
	if err != nil {
		t.Fatalf(err.Error())
		t.Fail()
		return
	}

	enced2, err := aesbuddy.AesCBCEncrpyt(key, data)
	if err != nil {
		t.Fatalf(err.Error())
		t.Fail()
		return
	}

	deced, err := aesbuddy.AesCBCDecrypt(key, enced)
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

	if slices.Compare(enced2, enced) == 0 {
		t.Log("enced2 == enced")
		t.Fail()
		return
	}

}

func TestAesCBC192(t *testing.T) {
	key := []byte("THIS IS MY KEY!!THIS IS ")
	data := []byte("MY SECRET MESSAGE")

	enced, err := aesbuddy.AesCBCEncrpyt(key, data)
	if err != nil {
		t.Fatalf(err.Error())
		t.Fail()
		return
	}

	enced2, err := aesbuddy.AesCBCEncrpyt(key, data)
	if err != nil {
		t.Fatalf(err.Error())
		t.Fail()
		return
	}

	deced, err := aesbuddy.AesCBCDecrypt(key, enced)
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

	if slices.Compare(enced2, enced) == 0 {
		t.Log("enced2 == enced")
		t.Fail()
		return
	}

}

func TestAesCBC256(t *testing.T) {
	key := []byte("THIS IS MY KEY!!THIS IS MY KEY!!")
	data := []byte("MY SECRET MESSAGE")

	enced, err := aesbuddy.AesCBCEncrpyt(key, data)
	if err != nil {
		t.Fatalf(err.Error())
		t.Fail()
		return
	}

	enced2, err := aesbuddy.AesCBCEncrpyt(key, data)
	if err != nil {
		t.Fatalf(err.Error())
		t.Fail()
		return
	}

	deced, err := aesbuddy.AesCBCDecrypt(key, enced)
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

	if slices.Compare(enced2, enced) == 0 {
		t.Log("enced2 == enced")
		t.Fail()
		return
	}

}
