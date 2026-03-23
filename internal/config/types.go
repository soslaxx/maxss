package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type Config struct {
	Name        string             `json:"NAME"`
	Listen      string             `json:"listen"`
	Port        int                `json:"port"`
	SNI         string             `json:"sni"`
	Transport   TransportConfig    `json:"transport"`
	Crypto      CryptoConfig       `json:"crypto"`
	Obfuscation ObfuscationConfig  `json:"obfuscation"`
	TLS         TLSConfig          `json:"tls"`
	Limits      LimitsConfig       `json:"limits"`
	Meta        map[string]string  `json:"meta,omitempty"`
}

type TransportConfig struct {
	Type          string   `json:"type"`
	Path          string   `json:"path"`
	ALPN          []string `json:"alpn"`
	ReadBufferKB  int      `json:"read_buffer_kb"`
	WriteBufferKB int      `json:"write_buffer_kb"`
	MaxFrameKB    int      `json:"max_frame_kb"`
}

type CryptoConfig struct {
	KDF                 string `json:"kdf"`
	KeyExchange         string `json:"key_exchange"`
	AEADOuter           string `json:"aead_outer"`
	AEADInner           string `json:"aead_inner"`
	Integrity           string `json:"integrity"`
	Mask                string `json:"mask"`
	RekeyIntervalFrames int    `json:"rekey_interval_frames"`
}

type ObfuscationConfig struct {
	PaddingMin   int `json:"padding_min"`
	PaddingMax   int `json:"padding_max"`
	JitterMS     int `json:"jitter_ms"`
	BurstPadding int `json:"burst_padding"`
}

type TLSConfig struct {
	CertFile           string `json:"cert_file"`
	KeyFile            string `json:"key_file"`
	MinVersion         string `json:"min_version"`
	PreferServerCipher bool   `json:"prefer_server_cipher"`
	SessionTickets     bool   `json:"session_tickets"`
}

type LimitsConfig struct {
	HandshakeTimeoutSec int `json:"handshake_timeout_sec"`
	IdleTimeoutSec      int `json:"idle_timeout_sec"`
	DialTimeoutSec      int `json:"dial_timeout_sec"`
	MaxConnections      int `json:"max_connections"`
}

type FileConfig struct {
	Path   string
	Config Config
}

func SecureDefaults(port int, sni, name string) Config {
	if strings.TrimSpace(name) == "" {
		name = "Secure Config"
	}
	if strings.TrimSpace(sni) == "" {
		sni = "www.cloudflare.com"
	}
	return Config{
		Name:   name,
		Listen: "0.0.0.0",
		Port:   port,
		SNI:    sni,
		Transport: TransportConfig{
			Type:          "tls-ws",
			Path:          "/.well-known/maxss",
			ALPN:          []string{"http/1.1"},
			ReadBufferKB:  256,
			WriteBufferKB: 256,
			MaxFrameKB:    128,
		},
		Crypto: CryptoConfig{
			KDF:                 "hkdf-sha512",
			KeyExchange:         "x25519",
			AEADOuter:           "aes-256-gcm",
			AEADInner:           "xchacha20-poly1305",
			Integrity:           "hmac-sha3-256",
			Mask:                "blake2b-xor",
			RekeyIntervalFrames: 4096,
		},
		Obfuscation: ObfuscationConfig{
			PaddingMin:   32,
			PaddingMax:   768,
			JitterMS:     2,
			BurstPadding: 2,
		},
		TLS: TLSConfig{
			MinVersion:         "1.3",
			PreferServerCipher: true,
			SessionTickets:     true,
		},
		Limits: LimitsConfig{
			HandshakeTimeoutSec: 10,
			IdleTimeoutSec:      180,
			DialTimeoutSec:      10,
			MaxConnections:      20000,
		},
		Meta: map[string]string{
			"profile":   "maximum-stealth-speed",
			"udp_relay": "enabled",
		},
	}
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("NAME is required")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}
	if strings.TrimSpace(c.SNI) == "" {
		return errors.New("sni is required")
	}
	if c.Transport.Type == "" {
		return errors.New("transport.type is required")
	}
	if c.Transport.Path == "" {
		return errors.New("transport.path is required")
	}
	if c.Transport.MaxFrameKB <= 0 {
		return errors.New("transport.max_frame_kb must be > 0")
	}
	if c.Obfuscation.PaddingMin < 0 || c.Obfuscation.PaddingMax < c.Obfuscation.PaddingMin {
		return errors.New("invalid obfuscation padding range")
	}
	if c.Limits.MaxConnections <= 0 {
		return errors.New("limits.max_connections must be > 0")
	}
	return nil
}

func (c Config) Clone() Config {
	b, _ := json.Marshal(c)
	var out Config
	_ = json.Unmarshal(b, &out)
	return out
}
