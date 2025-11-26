package models

import (
	"fmt"
	"log"

	"gopkg.in/ini.v1"
)

type Config struct {
	RouterHost     string
	RouterPort     int
	RouterUsername string
	RouterPassword string
	HostUsername   string
	HostPassword   string
	Debug          bool
}

func LoadConfig(filename string) (*Config, error) {
	cfg, err := ini.Load(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	config := &Config{
		RouterHost:     cfg.Section("router").Key("host").String(),
		RouterPort:     cfg.Section("router").Key("port").MustInt(8060),
		RouterUsername: cfg.Section("router").Key("username").String(),
		RouterPassword: cfg.Section("router").Key("password").String(),
		HostUsername:   cfg.Section("host").Key("username").String(),
		HostPassword:   cfg.Section("host").Key("password").String(),
		Debug:          cfg.Section("app").Key("debug").MustBool(false),
	}

	log.Printf("[CONFIG] Router: %s:%d, user=%s, pass=%s", config.RouterHost, config.RouterPort, config.RouterUsername, maskPassword(config.RouterPassword))
	log.Printf("[CONFIG] Host: user=%s, pass=%s", config.HostUsername, maskPassword(config.HostPassword))

	return config, nil
}

func maskPassword(pass string) string {
	if len(pass) <= 4 {
		return "***"
	}
	return pass[:2] + "***" + pass[len(pass)-2:]
}
