package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"aspia_rest_api/models"
	"aspia_rest_api/pkg/aspia"

	pb_router "aspia_rest_api/proto/router"
	pb_admin "aspia_rest_api/proto/router_admin"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type AspiaService struct {
	config *models.Config
}

func NewAspiaService(config *models.Config) *AspiaService {
	return &AspiaService{config: config}
}

type APIError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeJSONError(w http.ResponseWriter, message string, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(APIError{Error: message, Code: code})
}

func (s *AspiaService) GetHosts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Connect to router
	client := aspia.NewClient()
	address := fmt.Sprintf("%s:%d", s.config.RouterHost, s.config.RouterPort)

	routerUser, routerPass := s.getRouterCredentials(r)
	err := client.ConnectAdmin(address, routerUser, routerPass)
	if err != nil {
		errStr := err.Error()
		if containsAuthError(errStr) {
			writeJSONError(w, fmt.Sprintf("Router authentication failed: %v", err), "router_auth_failed", http.StatusUnauthorized)
			return
		}
		writeJSONError(w, fmt.Sprintf("Failed to connect to router: %v", err), "router_connection_failed", http.StatusInternalServerError)
		return
	}
	defer client.Disconnect()

	// Get hosts
	hosts, err := client.GetHosts()
	if err != nil {
		writeJSONError(w, fmt.Sprintf("Failed to get hosts: %v", err), "router_operation_failed", http.StatusInternalServerError)
		return
	}

	// Convert to API model
	hostInfos := make([]models.HostInfo, 0, len(hosts))
	for _, host := range hosts {
		var hostID uint64
		// Default to SessionId if we can't find HostID (though this might be wrong for connection)
		hostID = uint64(host.SessionId)

		if host.SessionType == pb_router.SessionType_SESSION_TYPE_HOST {
			var hostData pb_admin.HostSessionData
			if err := proto.Unmarshal(host.SessionData, &hostData); err == nil {
				if len(hostData.HostId) > 0 {
					hostID = hostData.HostId[0]
				}
			}
		}

		hostInfo := models.HostInfo{
			HostID:       hostID,
			SessionID:    host.SessionId,
			ComputerName: host.ComputerName,
			IPAddress:    host.IpAddress,
			OSName:       host.OsName,
			Architecture: host.Architecture,
		}
		if host.Version != nil {
			hostInfo.Version = fmt.Sprintf("%d.%d.%d.%d", host.Version.Major, host.Version.Minor, host.Version.Patch, host.Version.Revision)
		}
		hostInfos = append(hostInfos, hostInfo)
	}

	json.NewEncoder(w).Encode(hostInfos)
}

func (s *AspiaService) GetHostConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Get hostId from URL
	vars := mux.Vars(r)
	hostIdStr := vars["hostId"]
	hostId, err := strconv.ParseUint(hostIdStr, 10, 64)
	if err != nil {
		writeJSONError(w, "Invalid host ID", "bad_request", http.StatusBadRequest)
		return
	}

	// Connect to router
	client := aspia.NewClient()
	address := fmt.Sprintf("%s:%d", s.config.RouterHost, s.config.RouterPort)

	routerUser, routerPass := s.getRouterCredentials(r)
	err = client.Connect(address, routerUser, routerPass)
	if err != nil {
		errStr := err.Error()
		if containsAuthError(errStr) {
			writeJSONError(w, fmt.Sprintf("Router authentication failed: %v", err), "router_auth_failed", http.StatusUnauthorized)
			return
		}
		writeJSONError(w, fmt.Sprintf("Failed to connect to router: %v", err), "router_connection_failed", http.StatusInternalServerError)
		return
	}
	defer client.Disconnect()

	// Get System Info
	// Use host credentials from headers or config
	hostUser, hostPass := s.getHostCredentials(r)

	categoryParam := r.URL.Query().Get("category")
	var categoriesToFetch []string

	switch categoryParam {
	case "all":
		categoriesToFetch = []string{
			aspia.SystemInfoSummary,
			aspia.SystemInfoDevices,
			aspia.SystemInfoVideoAdapters,
			aspia.SystemInfoMonitors,
			aspia.SystemInfoPrinters,
			aspia.SystemInfoPowerOptions,
			aspia.SystemInfoDrivers,
			aspia.SystemInfoServices,
			aspia.SystemInfoEnvironmentVariables,
			aspia.SystemInfoEventLogs,
			aspia.SystemInfoNetworkAdapters,
			aspia.SystemInfoRoutes,
			aspia.SystemInfoConnections,
			aspia.SystemInfoNetworkShares,
			aspia.SystemInfoLicenses,
			aspia.SystemInfoApplications,
			aspia.SystemInfoOpenFiles,
			aspia.SystemInfoLocalUsers,
			aspia.SystemInfoLocalUserGroups,
			aspia.SystemInfoProcesses,
		}
	case "video_adapters":
		categoriesToFetch = []string{aspia.SystemInfoVideoAdapters}
	case "monitors":
		categoriesToFetch = []string{aspia.SystemInfoMonitors}
	case "printers":
		categoriesToFetch = []string{aspia.SystemInfoPrinters}
	case "applications":
		categoriesToFetch = []string{aspia.SystemInfoApplications}
	case "drivers":
		categoriesToFetch = []string{aspia.SystemInfoDrivers}
	case "services":
		categoriesToFetch = []string{aspia.SystemInfoServices}
	case "users":
		categoriesToFetch = []string{aspia.SystemInfoLocalUsers}
	case "summary", "":
		categoriesToFetch = []string{aspia.SystemInfoSummary}
	default:
		// Try to use as raw GUID or unknown category
		categoriesToFetch = []string{categoryParam}
	}

	sysInfo, err := client.GetSystemInfo(hostId, categoriesToFetch, hostUser, hostPass)

	if err != nil {
		// Check for authentication errors
		// Note: This relies on error string matching as the client might not return typed errors yet
		errStr := err.Error()
		if containsAuthError(errStr) {
			writeJSONError(w, fmt.Sprintf("Host authentication failed: %v", err), "host_auth_failed", http.StatusUnauthorized)
			return
		}
		writeJSONError(w, fmt.Sprintf("Failed to get system info: %v", err), "host_operation_failed", http.StatusInternalServerError)
		return
	}

	// Convert SystemInfo to JSON
	marshaler := protojson.MarshalOptions{
		EmitUnpopulated: false, // Don't emit null/zero values
		UseProtoNames:   true,
	}
	jsonBytes, err := marshaler.Marshal(sysInfo)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("Failed to marshal system info: %v", err), "internal_error", http.StatusInternalServerError)
		return
	}

	// Return response
	response := models.HostConfig{
		HostID:     hostId,
		SystemInfo: json.RawMessage(jsonBytes),
	}

	json.NewEncoder(w).Encode(response)
}

// Helper methods to extract credentials from headers or fallback to config

func (s *AspiaService) getRouterCredentials(r *http.Request) (string, string) {
	user := r.Header.Get("X-Aspia-Router-User")
	pass := r.Header.Get("X-Aspia-Router-Password")

	if user != "" {
		return user, pass
	}
	return s.config.RouterUsername, s.config.RouterPassword
}

func (s *AspiaService) getHostCredentials(r *http.Request) (string, string) {
	user := r.Header.Get("X-Aspia-Host-User")
	pass := r.Header.Get("X-Aspia-Host-Password")

	if user != "" {
		return user, pass
	}
	return s.config.HostUsername, s.config.HostPassword
}

func containsAuthError(errStr string) bool {
	// Simple check for common auth error keywords
	errStrLower := strings.ToLower(errStr)
	return strings.Contains(errStrLower, "authentication failed") ||
		strings.Contains(errStrLower, "access denied") ||
		strings.Contains(errStrLower, "bad credentials")
}
