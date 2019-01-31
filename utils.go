package main

import (
	"crypto/rand"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
)

func GenerateNumericID() (string, error) {
	chars := "1234567890"
	str := ""
	length := 9
	for i := 1; i <= length; i++ {
		rnum, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		c := string(chars[rnum.Int64()])
		str += c
	}
	return str, nil
}

func GenerateRandom(length int) string {
	chars := "abcdefghjkrtvxyz2346789"
	str := ""
	for i := 1; i <= length; i++ {
		rnum, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			panic(err)
		}
		c := string(chars[rnum.Int64()])
		str += c
	}
	return str
}

func GenerateID(prefix string) (string, error) {
	// Potentially confusing, so exclude:
	//     Look similar: 1 I l
	//     Look similar: 0 O
	//     Look similar: p q
	//     Look similar: 5 S
	//     Sound similar: U W
	//     Sound similar: M N
	length := 12 - len(prefix)
	chars := "abcdefghjkrtvxyz2346789"
	str := ""
	for i := 1; i <= length; i++ {
		rnum, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		c := string(chars[rnum.Int64()])
		str += c
	}
	return prefix + str, nil
}

func Overwrite(filename string, data []byte, perm os.FileMode) error {
	f, err := ioutil.TempFile(filepath.Dir(filename), filepath.Base(filename)+".tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(f.Name(), perm); err != nil {
		return err
	}
	return os.Rename(f.Name(), filename)
}
