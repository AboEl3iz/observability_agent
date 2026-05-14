// Package config manages the YAML configuration file stored at
// ~/.config/ebpf-observer/config.yaml.
package config

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	appDir     = "ebpf-observer"
	configFile = "config.yaml"
)

// Config holds all user-configurable settings.
// Fields map 1-to-1 with the YAML file keys so the file is human-editable.
type Config struct {
	// UI
	Theme     string `yaml:"theme"`      // builtin theme name
	RenderFPS int    `yaml:"render_fps"` // target UI frame rate (default 10)

	// Collection
	DataIntervalMs int `yaml:"data_interval_ms"` // collector poll period in ms

	// Filters (mirror the CLI flags)
	ContainersOnly bool `yaml:"containers_only"`
	TopN           int  `yaml:"top_n"`
	ShowTCP        bool `yaml:"show_tcp"`
	ShowFiles      bool `yaml:"show_files"`
	ShowSlowSys    bool `yaml:"show_slow_sys"`
}

// Default returns a Config with sensible production defaults.
func Default() Config {
	return Config{
		Theme:          "github-dark",
		RenderFPS:      10,
		DataIntervalMs: 1000,
	}
}

// RenderInterval converts RenderFPS to a time.Duration.
func (c Config) RenderInterval() time.Duration {
	if c.RenderFPS <= 0 {
		c.RenderFPS = 10
	}
	return time.Duration(1000/c.RenderFPS) * time.Millisecond
}

// DataInterval converts DataIntervalMs to a time.Duration.
func (c Config) DataInterval() time.Duration {
	if c.DataIntervalMs <= 0 {
		c.DataIntervalMs = 1000
	}
	return time.Duration(c.DataIntervalMs) * time.Millisecond
}

// Load reads the config file, returning Default() if it does not exist.
func Load() (Config, error) {
	path, err := configPath()
	if err != nil {
		return Default(), nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return Default(), err
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Default(), err
	}
	return cfg, nil
}

// Save persists cfg to the config file, creating directories as needed.
func Save(cfg Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// configPath returns the absolute path to the config file.
func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", appDir, configFile), nil
}
