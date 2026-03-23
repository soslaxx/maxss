package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var cfgFileRE = regexp.MustCompile(`^config(\d+)\.json$`)

func EnsureConfigDir(dir string) error {
	if dir == "" {
		return errors.New("config dir is empty")
	}
	return os.MkdirAll(dir, 0o750)
}

func LoadAll(dir string) ([]FileConfig, error) {
	if err := EnsureConfigDir(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read config dir: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if cfgFileRE.MatchString(e.Name()) {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Slice(files, func(i, j int) bool {
		return configIndex(files[i]) < configIndex(files[j])
	})

	out := make([]FileConfig, 0, len(files))
	for _, file := range files {
		cfg, err := LoadFile(file)
		if err != nil {
			return nil, err
		}
		out = append(out, FileConfig{Path: file, Config: cfg})
	}
	return out, nil
}

func LoadFile(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

func SaveConfig(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o640)
}

func NextConfigPath(dir string) (string, int, error) {
	if err := EnsureConfigDir(dir); err != nil {
		return "", 0, err
	}
	maxN := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		m := cfgFileRE.FindStringSubmatch(base)
		if len(m) != 2 {
			return nil
		}
		n, _ := strconv.Atoi(m[1])
		if n > maxN {
			maxN = n
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	next := maxN + 1
	return filepath.Join(dir, fmt.Sprintf("config%d.json", next)), next, nil
}

func NameExists(dir, name string) (bool, error) {
	all, err := LoadAll(dir)
	if err != nil {
		return false, err
	}
	for _, fc := range all {
		if strings.EqualFold(strings.TrimSpace(fc.Config.Name), strings.TrimSpace(name)) {
			return true, nil
		}
	}
	return false, nil
}

func EnsureUniqueName(dir, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Secure Config"
	}
	exists, err := NameExists(dir, name)
	if err != nil {
		return "", err
	}
	if !exists {
		return name, nil
	}
	for i := 2; i < 10000; i++ {
		candidate := fmt.Sprintf("%s %d", name, i)
		exists, err := NameExists(dir, candidate)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
	return "", errors.New("unable to find unique config name")
}

func CreateSecureConfig(dir string, port int, sni, name string) (string, Config, error) {
	uniqName, err := EnsureUniqueName(dir, name)
	if err != nil {
		return "", Config{}, err
	}
	cfg := SecureDefaults(port, sni, uniqName)
	path, _, err := NextConfigPath(dir)
	if err != nil {
		return "", Config{}, err
	}
	if err := SaveConfig(path, cfg); err != nil {
		return "", Config{}, err
	}
	return path, cfg, nil
}

func DeleteConfig(path string) error {
	if !cfgFileRE.MatchString(filepath.Base(path)) {
		return errors.New("refusing to delete non configN.json file")
	}
	return os.Remove(path)
}

func FindByName(dir, name string) (*FileConfig, error) {
	all, err := LoadAll(dir)
	if err != nil {
		return nil, err
	}
	for _, fc := range all {
		if strings.EqualFold(strings.TrimSpace(fc.Config.Name), strings.TrimSpace(name)) {
			copy := fc
			return &copy, nil
		}
	}
	return nil, nil
}

func configIndex(path string) int {
	base := filepath.Base(path)
	m := cfgFileRE.FindStringSubmatch(base)
	if len(m) != 2 {
		return 1<<31 - 1
	}
	n, _ := strconv.Atoi(m[1])
	return n
}
