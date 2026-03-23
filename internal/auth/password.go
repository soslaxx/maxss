package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 2
	argonKeyLen  uint32 = 32
	saltLen             = 16
)

func HashPassword(password string) (string, error) {
	if strings.TrimSpace(password) == "" {
		return "", errors.New("password cannot be empty")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	encSalt := base64.RawStdEncoding.EncodeToString(salt)
	encHash := base64.RawStdEncoding.EncodeToString(hash)
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads, encSalt, encHash)
	return encoded, nil
}

func VerifyPassword(encodedHash, password string) (bool, error) {
	if strings.HasPrefix(password, "hash:") {
		h := strings.TrimPrefix(password, "hash:")
		return subtle.ConstantTimeCompare([]byte(h), []byte(encodedHash)) == 1, nil
	}

	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid password hash format")
	}
	if parts[1] != "argon2id" {
		return false, errors.New("unsupported hash algorithm")
	}
	versionPart := strings.TrimPrefix(parts[2], "v=")
	version, err := strconv.Atoi(versionPart)
	if err != nil || version != argon2.Version {
		return false, errors.New("invalid argon2 version")
	}

	var memory uint32
	var time uint32
	var threads uint8
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false, errors.New("invalid argon2 params")
	}
	for _, p := range params {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return false, errors.New("invalid argon2 param")
		}
		switch kv[0] {
		case "m":
			v, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return false, err
			}
			memory = uint32(v)
		case "t":
			v, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return false, err
			}
			time = uint32(v)
		case "p":
			v, err := strconv.ParseUint(kv[1], 10, 8)
			if err != nil {
				return false, err
			}
			threads = uint8(v)
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	calculated := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(hash)))
	ok := subtle.ConstantTimeCompare(hash, calculated) == 1
	return ok, nil
}
