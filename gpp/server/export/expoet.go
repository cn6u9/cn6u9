package main

import (
	"encoding/json"
	"fmt"
	"github.com/danbai225/gpp/server/core"
	"github.com/google/uuid"
	"os"
)

func init() {
	Server()
}

//export Server
func Server() {
	bytes, err := os.ReadFile("config.json")
	if err != nil {
		fmt.Println("read config err:", err)
	}
	config := core.Peer{}
	_ = json.Unmarshal(bytes, &config)
	if config.Port == 0 {
		config.Port = 34555
	}
	if config.Addr == "" {
		config.Addr = "0.0.0.0"
	}
	if config.UUID == "" {
		config.UUID = uuid.New().String()
	}
	_ = core.Server(config)
}
func main() {}
