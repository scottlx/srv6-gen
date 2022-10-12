package conf

import (
	"encoding/json"
	"io"
	"os"
)

type Config struct {
	Device        string   `json:"device"`
	L2Src         string   `json:"l2Src"`
	L2Dst         string   `json:"l2Dst"`
	UnderlayV6Dst string   `json:"underlayV6Dst"`
	UnderlayV6Src string   `json:"underlayV6Src"`
	OverlayV4Dst  string   `json:"overlayV4Dst"`
	OverlayV4Src  string   `json:"overlayV4Src"`
	SrhAddresses  []string `json:"srhAddresses"`
	PayLoad       string   `json:"payload"`
	EncapApn6     bool     `json:"encapApn6"`
}

func LoadConfig(path string) (config *Config, err error) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	jsonStr, err := io.ReadAll(file)
	if err != nil {
		return
	}

	config = &Config{}
	if err = json.Unmarshal(jsonStr, config); err != nil {
		return nil, err
	}
	return
}
