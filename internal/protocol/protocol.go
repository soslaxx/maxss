package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	Version = 1
)

const (
	MsgConnect   byte = 0x01
	MsgData      byte = 0x02
	MsgClose     byte = 0x03
	MsgPing      byte = 0x04
	MsgConnectOK byte = 0x05
	MsgError     byte = 0x06
)

type HandshakeRequest struct {
	Version    int   `json:"version"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	ConfigName string `json:"config_name"`
	ClientPub  string `json:"client_pub"`
	Salt       string `json:"salt"`
	Timestamp  int64  `json:"timestamp"`
}

type HandshakeResponse struct {
	OK        bool     `json:"ok"`
	Error     string   `json:"error,omitempty"`
	ServerPub string   `json:"server_pub,omitempty"`
	SessionID string   `json:"session_id,omitempty"`
	Features  []string `json:"features,omitempty"`
}

type SessionCipher struct {
	aesgcm   cipher.AEAD
	xchacha  cipher.AEAD
	hmacKey  []byte
	maskKey  []byte
	nonceKey []byte

	padMin int
	padMax int

	sendCounter uint64
	recvCounter uint64
	mu          sync.Mutex
}

func GenerateX25519Key() (*ecdh.PrivateKey, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

func DecodePublicKey(b64 string) (*ecdh.PublicKey, error) {
	b, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(b)
}

func DecodeSalt(b64 string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(b64)
}

func DeriveShared(priv *ecdh.PrivateKey, peer *ecdh.PublicKey) ([]byte, error) {
	return priv.ECDH(peer)
}

func DeriveSessionCipher(sharedSecret, salt []byte, context string, padMin, padMax int) (*SessionCipher, error) {
	if len(sharedSecret) == 0 {
		return nil, errors.New("empty shared secret")
	}
	if padMin < 0 {
		padMin = 0
	}
	if padMax < padMin {
		padMax = padMin
	}

	info := []byte("maxss-v1|" + context)
	h := hkdf.New(sha512.New, sharedSecret, salt, info)
	k := make([]byte, 32*5)
	if _, err := io.ReadFull(h, k); err != nil {
		return nil, err
	}

	aesBlock, err := aes.NewCipher(k[0:32])
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}

	xChaCha, err := chacha20poly1305.NewX(k[32:64])
	if err != nil {
		return nil, err
	}

	return &SessionCipher{
		aesgcm:   aesGCM,
		xchacha:  xChaCha,
		hmacKey:  append([]byte(nil), k[64:96]...),
		maskKey:  append([]byte(nil), k[96:128]...),
		nonceKey: append([]byte(nil), k[128:160]...),
		padMin:   padMin,
		padMax:   padMax,
	}, nil
}

func (s *SessionCipher) Encrypt(plain []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sendCounter++
	ctr := s.sendCounter

	padLen, err := s.paddingLength()
	if err != nil {
		return nil, err
	}

	body := make([]byte, 6+len(plain)+padLen)
	binary.BigEndian.PutUint32(body[0:4], uint32(len(plain)))
	binary.BigEndian.PutUint16(body[4:6], uint16(padLen))
	copy(body[6:], plain)
	if padLen > 0 {
		if _, err := rand.Read(body[6+len(plain):]); err != nil {
			return nil, err
		}
	}

	nonceA := deriveNonce(s.nonceKey, ctr, 'A', 12)
	layer1 := s.aesgcm.Seal(nil, nonceA, body, nil)

	nonceB := deriveNonce(s.nonceKey, ctr, 'B', 24)
	layer2 := s.xchacha.Seal(nil, nonceB, layer1, nil)

	masked, err := xorMask(layer2, s.maskKey, ctr)
	if err != nil {
		return nil, err
	}

	header := make([]byte, 12)
	binary.BigEndian.PutUint64(header[0:8], ctr)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(masked)))

	mac := hmacSHA3(s.hmacKey, header, masked)
	out := make([]byte, 0, len(header)+len(mac)+len(masked))
	out = append(out, header...)
	out = append(out, mac...)
	out = append(out, masked...)
	return out, nil
}

func (s *SessionCipher) Decrypt(frame []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(frame) < 12+32 {
		return nil, errors.New("frame too short")
	}
	header := frame[:12]
	tag := frame[12:44]
	payload := frame[44:]

	counter := binary.BigEndian.Uint64(header[0:8])
	if counter <= s.recvCounter {
		return nil, errors.New("replayed or out-of-order frame")
	}
	declared := binary.BigEndian.Uint32(header[8:12])
	if int(declared) != len(payload) {
		return nil, errors.New("frame size mismatch")
	}

	expected := hmacSHA3(s.hmacKey, header, payload)
	if !hmac.Equal(tag, expected) {
		return nil, errors.New("integrity check failed")
	}

	unmasked, err := xorMask(payload, s.maskKey, counter)
	if err != nil {
		return nil, err
	}
	nonceB := deriveNonce(s.nonceKey, counter, 'B', 24)
	layer1, err := s.xchacha.Open(nil, nonceB, unmasked, nil)
	if err != nil {
		return nil, fmt.Errorf("xchacha decrypt: %w", err)
	}

	nonceA := deriveNonce(s.nonceKey, counter, 'A', 12)
	body, err := s.aesgcm.Open(nil, nonceA, layer1, nil)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm decrypt: %w", err)
	}
	if len(body) < 6 {
		return nil, errors.New("decrypted body too short")
	}

	payloadLen := int(binary.BigEndian.Uint32(body[0:4]))
	padLen := int(binary.BigEndian.Uint16(body[4:6]))
	if payloadLen < 0 || padLen < 0 || payloadLen+padLen+6 > len(body) {
		return nil, errors.New("invalid decrypted lengths")
	}
	plain := make([]byte, payloadLen)
	copy(plain, body[6:6+payloadLen])
	s.recvCounter = counter
	return plain, nil
}

func EncodeMessage(msgType byte, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = msgType
	copy(out[1:], payload)
	return out
}

func DecodeMessage(data []byte) (msgType byte, payload []byte, err error) {
	if len(data) < 1 {
		return 0, nil, errors.New("empty message")
	}
	return data[0], data[1:], nil
}

func ValidateClientTimestamp(ts int64, window time.Duration) bool {
	d := time.Since(time.Unix(ts, 0))
	if d < 0 {
		d = -d
	}
	return d <= window
}

func hmacSHA3(key []byte, chunks ...[]byte) []byte {
	m := hmac.New(sha3.New256, key)
	for _, c := range chunks {
		_, _ = m.Write(c)
	}
	return m.Sum(nil)
}

func deriveNonce(nonceKey []byte, counter uint64, label byte, size int) []byte {
	seed := make([]byte, 9)
	binary.BigEndian.PutUint64(seed[:8], counter)
	seed[8] = label
	mix := make([]byte, 0, len(nonceKey)+len(seed))
	mix = append(mix, nonceKey...)
	mix = append(mix, seed...)
	sum := blake2b.Sum512(mix)
	out := make([]byte, size)
	copy(out, sum[:size])
	return out
}

func xorMask(src, maskKey []byte, counter uint64) ([]byte, error) {
	state := make([]byte, 8)
	binary.BigEndian.PutUint64(state, counter)
	h, err := blake2b.New512(maskKey)
	if err != nil {
		return nil, err
	}
	_, _ = h.Write(state)
	mask := h.Sum(nil)

	out := make([]byte, len(src))
	for i := range src {
		out[i] = src[i] ^ mask[i%len(mask)]
	}
	return out, nil
}

func (s *SessionCipher) paddingLength() (int, error) {
	if s.padMax <= s.padMin {
		return s.padMin, nil
	}
	rangeN := s.padMax - s.padMin + 1
	if rangeN <= 1 {
		return s.padMin, nil
	}
	v := make([]byte, 2)
	if _, err := rand.Read(v); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(v))
	return s.padMin + (n % rangeN), nil
}

func EncodePubB64(pub []byte) string {
	return base64.RawStdEncoding.EncodeToString(pub)
}

func EncodeSaltB64(s []byte) string {
	return base64.RawStdEncoding.EncodeToString(s)
}

func RandomSalt(size int) ([]byte, error) {
	if size <= 0 {
		size = 32
	}
	out := make([]byte, size)
	_, err := rand.Read(out)
	return out, err
}

func ParseConnectPayload(payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", errors.New("empty connect payload")
	}
	if len(payload) > 1024 {
		return "", errors.New("connect payload too long")
	}
	return string(bytes.TrimSpace(payload)), nil
}
