package sdtl

import (
	"encoding/json"
	"os"
)

type ServerConfig struct {
	Listen     string `json:"listen"`
	Port       int    `json:"port"`
	PrivateKey string `json:"private_key"`
}

type HostConfig struct {
	IP        string `json:"ip"`
	PublicKey string `json:"public_key"`
}

type Config struct {
	Server ServerConfig `json:"server"`
	Hosts  []HostConfig `json:"hosts"`
}

func ParseConfig(filePath string) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	config := &Config{}
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}

	return config, nil
}
