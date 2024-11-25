package config

import (
	"gopkg.in/yaml.v3"
	"os"
)

// Config represents the overall configuration structure
type Config struct {
	Listens []ListenConfig `yaml:"listens"`
}

// ListenConfig represents the configuration for each listener
type ListenConfig struct {
	Address   string          `yaml:"address"`
	Port      int             `yaml:"port"`
	TLSCACert string          `yaml:"tls_ca_cert"`
	TLSCert   string          `yaml:"tls_cert"`
	TLSKey    string          `yaml:"tls_key"`
	Backends  []BackendConfig `yaml:"backends"`
}

// BackendConfig represents the configuration for each backend
type BackendConfig struct {
	Address           string `yaml:"address"`
	Port              int    `yaml:"port"`
	Scheme            string `yaml:"scheme"`
	SkipVerifyTLSCert bool   `yaml:"skip_verify_tls_cert"`
	TLSCACert         string `yaml:"tls_ca_cert"`
}

// LoadConfig reads and parses the configuration file
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
