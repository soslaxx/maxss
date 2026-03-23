package subscription

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"maxss/internal/config"
	"maxss/internal/db"
)

type Endpoint struct {
	Name      string   `json:"name"`
	Address   string   `json:"address"`
	Port      int      `json:"port"`
	SNI       string   `json:"sni"`
	Transport string   `json:"transport"`
	Path      string   `json:"path"`
	ALPN      []string `json:"alpn"`
}

type Payload struct {
	Protocol     string     `json:"protocol"`
	Version      int        `json:"version"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"password_hash"`
	AuthMode     string     `json:"auth_mode"`
	Endpoints    []Endpoint `json:"endpoints"`
	CreatedAt    string     `json:"created_at"`
}

func Generate(user db.User, cfgs []config.FileConfig, addressOverride string) (string, error) {
	allowed := splitCSV(user.AllowedConfigs)
	endpoints := make([]Endpoint, 0)
	for _, fc := range cfgs {
		if !containsFold(allowed, fc.Config.Name) {
			continue
		}
		addr := strings.TrimSpace(addressOverride)
		if addr == "" {
			addr = fc.Config.SNI
		}
		endpoints = append(endpoints, Endpoint{
			Name:      fc.Config.Name,
			Address:   addr,
			Port:      fc.Config.Port,
			SNI:       fc.Config.SNI,
			Transport: fc.Config.Transport.Type,
			Path:      fc.Config.Transport.Path,
			ALPN:      fc.Config.Transport.ALPN,
		})
	}
	if len(endpoints) == 0 {
		return "", fmt.Errorf("user has no matching allowed configs")
	}
	payload := Payload{
		Protocol:     "maxss",
		Version:      1,
		Username:     user.Username,
		PasswordHash: user.PasswordHash,
		AuthMode:     "hash",
		Endpoints:    endpoints,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return "maxss://" + base64.RawURLEncoding.EncodeToString(b), nil
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func containsFold(items []string, v string) bool {
	v = strings.TrimSpace(v)
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), v) {
			return true
		}
	}
	return false
}
