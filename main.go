package main

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"
)

const EncryptionKey = "43"
const EncryptedFileExtension = ".Radiyu"

func CalculateHash(key string) []byte {
	hash := sha256.New()
	hash.Write([]byte(key))
	return hash.Sum(nil)
}

func pkcs7UnPad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}
	return data[:length-padLen], nil
}

func decrypt(path string, key []byte) error {
	fmt.Println("복호화 중: " + path)
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decrypted := make([]byte, len(fileBytes))
	if len(fileBytes)%aes.BlockSize != 0 {
		return errors.New("decrypt: Data is not block-aligned")
	}
	for i := 0; i < len(fileBytes); i += aes.BlockSize {
		aesCipher.Decrypt(decrypted[i:i+aes.BlockSize], fileBytes[i:i+aes.BlockSize])
	}
	decrypted, err = pkcs7UnPad(decrypted, aes.BlockSize)
	if err != nil {
		return err
	}

	path = strings.TrimSuffix(path, EncryptedFileExtension)
	err = os.WriteFile(path, decrypted, 0644)
	if err != nil {
		return err
	}
	err = os.Remove(path + EncryptedFileExtension)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	key := CalculateHash(EncryptionKey)
	failedFiles := make([]string, 0)
	succeedFiles := make([]string, 0)
	stack := make([]string, 0)
	myself, err := user.Current()
	if err != nil {
		panic(err)
	}
	stack = append(stack, myself.HomeDir+"/Desktop/")
	for len(stack) > 0 {
		dir := stack[0]
		stack = stack[1:]
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, file := range files {
			if file.IsDir() {
				stack = append(stack, dir+"/"+file.Name())
			} else if strings.HasSuffix(file.Name(), EncryptedFileExtension) {
				err := decrypt(dir+file.Name(), key)
				if err != nil {
					failedFiles = append(failedFiles, dir+file.Name())
				} else {
					succeedFiles = append(succeedFiles, dir+file.Name())
				}
			}
		}
	}
	fmt.Println("복호화가 끝났어요!")
	fmt.Println("성공한 파일들:")
	for _, file := range succeedFiles {
		fmt.Println(file)
	}
	fmt.Println("실패한 파일들:")
	for _, file := range failedFiles {
		fmt.Println(file)
	}
	fmt.Println("엔터 키를 눌러 종료하세요...")
	_, _ = fmt.Scanln()
}
