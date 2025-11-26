package models

import "encoding/json"

type HostInfo struct {
	HostID       uint64 `json:"host_id"`
	SessionID    int64  `json:"session_id"`
	ComputerName string `json:"computer_name"`
	IPAddress    string `json:"ip_address"`
	OSName       string `json:"os_name"`
	Architecture string `json:"architecture"`
	Version      string `json:"version"`
}

type HostConfig struct {
	HostID     uint64          `json:"host_id"`
	SystemInfo json.RawMessage `json:"system_info"`
	Error      string          `json:"error,omitempty"`
}
