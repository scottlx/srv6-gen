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
	OverlayV6Dst  string   `json:"overlayV6Dst"`
	OverlayV6Src  string   `json:"overlayV6Src"`
	UnderlayV4Dst string   `json:"underlayV4Dst"`
	UnderlayV4Src string   `json:"underlayV4Src"`
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
