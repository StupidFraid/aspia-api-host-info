package aspia

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"google.golang.org/protobuf/proto"

	"aspia_rest_api/pkg/aspia/crypto"

	pb_key "aspia_rest_api/proto/key_exchange"
	pb_peer "aspia_rest_api/proto/peer"
	pb_router "aspia_rest_api/proto/router"
	pb_admin "aspia_rest_api/proto/router_admin"
	pb_rpeer "aspia_rest_api/proto/router_peer"
	pb_sys "aspia_rest_api/proto/system_info"
)

const (
	AspiaVersionMajor = 2
	AspiaVersionMinor = 7
	AspiaVersionPatch = 0
	AspiaRevision     = 0
)

type Client struct {
	conn *Connection

	// Auth state
	username string
	password string

	// SRP state
	a, A, S, K *big.Int

	// Session info
	SessionID       int64
	ProtocolVersion *pb_peer.Version
}

const (
	SystemInfoSummary              = "D9FE7CED-175C-4069-AB80-9B4F897EB376"
	SystemInfoDevices              = "1451B77D-276E-47BB-989B-D8B61A468F8B"
	SystemInfoVideoAdapters        = "D2867BED-1408-467C-8ABE-6BD8B32DE17B"
	SystemInfoMonitors             = "344E1796-EFF2-4F4D-B48B-3A10CEA834B8"
	SystemInfoPrinters             = "19193E9A-D2A6-44F8-83D2-A6B0F8651DAC"
	SystemInfoPowerOptions         = "838C76EA-D13F-4718-8C7E-D483221ECF99"
	SystemInfoDrivers              = "82E18359-39CC-41FA-A8DA-70077F1340FB"
	SystemInfoServices             = "F56D910E-9A08-4459-8F11-F0F42817F0CD"
	SystemInfoEnvironmentVariables = "F06EA182-23FB-4347-9C9E-F66582C9EF71"
	SystemInfoEventLogs            = "8F2499F5-30B8-42B5-82DF-6FBE0BCCDD6F"
	SystemInfoNetworkAdapters      = "A27B3B0E-BF55-43B3-989B-40705DAF3290"
	SystemInfoRoutes               = "224C9198-FF86-40B6-96FD-19938B952021"
	SystemInfoConnections          = "E720729A-7C96-4603-A46B-91FBC95420D6"
	SystemInfoNetworkShares        = "EC295A1A-6CBD-4334-9697-38E542687902"
	SystemInfoLicenses             = "7D3320B3-E5A6-43AD-8768-09F9304CEFC7"
	SystemInfoApplications         = "E2057608-971B-439C-9A2E-31CB0BA6C6CC"
	SystemInfoOpenFiles            = "F851332D-D70E-4D68-A30D-7A3F00E69324"
	SystemInfoLocalUsers           = "00489EAB-09BF-4BB2-837C-0F975183698F"
	SystemInfoLocalUserGroups      = "FDB3703C-A943-4A0B-873F-B980B0ACA0E5"
	SystemInfoProcesses            = "91165E05-A152-4B07-B988-EF8E48DA66C3"
)

func NewClient() *Client {
	return &Client{}
}

func (c *Client) Connect(address, username, password string) error {
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return err
	}
	c.conn = NewConnection(conn)
	c.username = username
	c.password = password

	return c.authenticate(pb_router.SessionType_SESSION_TYPE_CLIENT)
}

func (c *Client) authenticate(sessionType pb_router.SessionType) error {
	// 1. Send ClientHello
	clientHello := &pb_key.ClientHello{
		Encryption: uint32(pb_key.Encryption_ENCRYPTION_CHACHA20_POLY1305) | uint32(pb_key.Encryption_ENCRYPTION_AES256_GCM),
		Identify:   pb_key.Identify_IDENTIFY_SRP,
		Version: &pb_peer.Version{
			Major:    AspiaVersionMajor,
			Minor:    AspiaVersionMinor,
			Patch:    AspiaVersionPatch,
			Revision: AspiaRevision,
		},
	}

	data, err := proto.Marshal(clientHello)
	if err != nil {
		return err
	}

	if err := c.conn.WriteMessage(0, data); err != nil {
		return err
	}

	// 2. Read ServerHello
	DebugLog("[DEBUG] Waiting for ServerHello...")
	serverHello := &pb_key.ServerHello{}
	if err := c.conn.ReadMessageProto(serverHello); err != nil {
		return fmt.Errorf("failed to read ServerHello: %w", err)
	}

	// 3. Send Identify
	identify := &pb_key.SrpIdentify{
		Username: c.username,
	}
	data, err = proto.Marshal(identify)
	if err != nil {
		return err
	}
	if err := c.conn.WriteMessage(0, data); err != nil {
		return err
	}

	// 4. Read ServerKeyExchange
	_, data, err = c.conn.ReadMessage()
	if err != nil {
		return err
	}

	serverKeyExchange := &pb_key.SrpServerKeyExchange{}
	if err := proto.Unmarshal(data, serverKeyExchange); err != nil {
		return err
	}

	// 5. SRP Calculation
	N := new(big.Int).SetBytes(serverKeyExchange.Number)
	g := new(big.Int).SetBytes(serverKeyExchange.Generator)
	s := serverKeyExchange.Salt
	B := new(big.Int).SetBytes(serverKeyExchange.B)

	if !crypto.VerifyNg(N, g) {
		log.Printf("[ERROR] Invalid SRP group parameters!")
		log.Printf("[ERROR] N (%d bits): %x", N.BitLen(), N.Bytes())
		log.Printf("[ERROR] g: %x", g.Bytes())
		return errors.New("invalid SRP group parameters")
	}

	// Use the size of N from the server message for padding
	size := len(serverKeyExchange.Number)

	// Generate 'a' as 128 bytes (1024 bits) matching C++ implementation
	// C++: a_ = BigNum::fromByteArray(Random::byteArray(128));
	aBytes, _ := crypto.GenerateRandomBytes(128)
	c.a = new(big.Int).SetBytes(aBytes)
	c.A = crypto.CalcA(c.a, N, g)
	u := crypto.CalcU(c.A, B, N, size)
	DebugLog("[DEBUG SRP] Using username=%q, password=%q", c.username, c.password)
	x := crypto.CalcX(s, c.username, c.password)
	k := crypto.CalcK(N, g, size)
	c.S = crypto.CalcClientSessionKey(N, g, k, x, u, c.a, B)
	DebugLog("[DEBUG SRP] N bits: %d, B bits: %d, A bits: %d, S bits: %d", N.BitLen(), B.BitLen(), c.A.BitLen(), c.S.BitLen())
	DebugLog("[DEBUG SRP] S (first 32 bytes): %x", c.S.Bytes()[:32])

	// 6. Send ClientKeyExchange
	encryptIv, _ := crypto.GenerateRandomBytes(12)

	clientKeyExchange := &pb_key.SrpClientKeyExchange{
		A:  c.A.Bytes(),
		Iv: encryptIv,
	}

	data, err = proto.Marshal(clientKeyExchange)
	if err != nil {
		return err
	}
	DebugLog("[DEBUG] Sending ClientKeyExchange with A (bits=%d), IV=%x", c.A.BitLen(), encryptIv)
	if err := c.conn.WriteMessage(0, data); err != nil {
		return err
	}

	// 7. Enable Encryption
	sessionKey := crypto.HashBlake2s256(c.S.Bytes())
	decryptIv := serverKeyExchange.Iv

	var encryptor crypto.Encryptor
	var decryptor crypto.Decryptor

	if serverHello.Encryption == pb_key.Encryption_ENCRYPTION_CHACHA20_POLY1305 {
		encryptor, err = crypto.NewChaCha20Poly1305Encryptor(sessionKey, encryptIv)
		if err != nil {
			return err
		}
		decryptor, err = crypto.NewChaCha20Poly1305Decryptor(sessionKey, decryptIv)
		if err != nil {
			return err
		}
	} else {
		encryptor, err = crypto.NewAES256GCMEncryptor(sessionKey, encryptIv)
		if err != nil {
			return err
		}
		decryptor, err = crypto.NewAES256GCMDecryptor(sessionKey, decryptIv)
		if err != nil {
			return err
		}
	}

	c.conn.SetEncryption(encryptor, decryptor)
	DebugLog("[DEBUG] Session key length: %d, encryptIv length: %d, decryptIv length: %d", len(sessionKey), len(encryptIv), len(decryptIv))
	DebugLog("[DEBUG] Session key: %x", sessionKey)
	DebugLog("[DEBUG] Encrypt IV: %x", encryptIv)
	DebugLog("[DEBUG] Decrypt IV: %x", decryptIv)

	// 8. Read SessionChallenge
	DebugLog("[DEBUG] Waiting for SessionChallenge (encrypted)...")
	_, challengeData, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read SessionChallenge: %w", err)
	}
	DebugLog("[DEBUG] Received encrypted SessionChallenge, length: %d", len(challengeData))

	sessionChallenge := &pb_key.SessionChallenge{}
	if err := proto.Unmarshal(challengeData, sessionChallenge); err != nil {
		return err
	}

	// Check version for protocol compatibility
	// Aspia < 2.6 uses encrypted headers
	if sessionChallenge.Version != nil {
		c.ProtocolVersion = sessionChallenge.Version
		DebugLog("[DEBUG] SessionChallenge Version: %d.%d.%d.%d", sessionChallenge.Version.Major, sessionChallenge.Version.Minor, sessionChallenge.Version.Patch, sessionChallenge.Version.Revision)
		if sessionChallenge.Version.Major < 2 || (sessionChallenge.Version.Major == 2 && sessionChallenge.Version.Minor < 6) {
			c.conn.HeaderEncrypted = true
			DebugLog("[DEBUG] Detected older Aspia version (%d.%d.%d), enabling HeaderEncrypted",
				sessionChallenge.Version.Major, sessionChallenge.Version.Minor, sessionChallenge.Version.Patch)
		}
	} else {
		DebugLog("[DEBUG] SessionChallenge Version is nil")
	}

	// 9. Send SessionResponse
	sessionResponse := &pb_key.SessionResponse{
		SessionType: uint32(sessionType),
		Version: &pb_peer.Version{
			Major:    AspiaVersionMajor,
			Minor:    AspiaVersionMinor,
			Patch:    AspiaVersionPatch,
			Revision: AspiaRevision,
		},
		OsName:       "linux",
		ComputerName: "aspia-go-client",
		CpuCores:     4,
		DisplayName:  "Aspia Go Client",
		Arch:         "x86_64",
	}

	data, err = proto.Marshal(sessionResponse)
	if err != nil {
		return err
	}
	if err := c.conn.WriteMessage(0, data); err != nil {
		return err
	}

	// ChannelID is only supported in Aspia >= 2.6
	// PCAP analysis shows Agent 2.5.2 doesn't use Channel ID header
	if c.ProtocolVersion != nil {
		if c.ProtocolVersion.Major >= 2 && c.ProtocolVersion.Minor >= 6 {
			c.conn.ChannelIdSupported = true
			DebugLog("[DEBUG] Enabling ChannelID for Aspia >= 2.6")
		} else {
			c.conn.ChannelIdSupported = false
			DebugLog("[DEBUG] Disabling ChannelID for Aspia < 2.6 (version %d.%d.%d)",
				c.ProtocolVersion.Major, c.ProtocolVersion.Minor, c.ProtocolVersion.Patch)
		}
	} else {
		// Default to enabled if version unknown
		c.conn.ChannelIdSupported = true
	}

	// Add a small delay to ensure server processes SessionResponse and enables Channel ID
	time.Sleep(100 * time.Millisecond)

	return nil
}

func (c *Client) Disconnect() error {
	return c.conn.Close()
}

// GetHosts fetches the list of hosts from the Router
func (c *Client) GetHosts() ([]*pb_admin.Session, error) {
	// Send SessionListRequest
	req := &pb_admin.AdminToRouter{
		SessionListRequest: &pb_admin.SessionListRequest{
			Dummy: 1,
		},
	}

	data, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	if err := c.conn.WriteMessage(uint8(pb_peer.ChannelId_CHANNEL_ID_SESSION), data); err != nil {
		return nil, err
	}

	// Read response
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			return nil, err
		}

		msg := &pb_admin.RouterToAdmin{}
		if err := proto.Unmarshal(data, msg); err != nil {
			return nil, err
		}

		if msg.SessionList != nil {
			return msg.SessionList.Session, nil
		}
	}
}

func (c *Client) ConnectAdmin(address, username, password string) error {
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return err
	}
	c.conn = NewConnection(conn)
	c.username = username
	c.password = password

	return c.authenticate(pb_router.SessionType_SESSION_TYPE_ADMIN)
}

// GetSystemInfo fetches system info from a host
func (c *Client) GetSystemInfo(hostID uint64, categories []string, hostUsername, hostPassword string) (*pb_sys.SystemInfo, error) {
	// 1. Connect to Router (Client Role)
	// We need a fresh connection to the Router for the Client session
	if c.conn == nil || c.conn.conn == nil {
		return nil, errors.New("client not connected (need router address)")
	}
	routerAddr := c.conn.conn.RemoteAddr().String()

	clientConn, err := net.DialTimeout("tcp", routerAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer clientConn.Close()

	// Create a temporary Client for the Router connection
	routerClient := &Client{
		conn:     NewConnection(clientConn),
		username: c.username,
		password: c.password,
	}

	// Authenticate as CLIENT
	if err := routerClient.authenticate(pb_router.SessionType_SESSION_TYPE_CLIENT); err != nil {
		return nil, fmt.Errorf("router authentication failed: %w", err)
	}

	// Send ConnectionRequest
	req := &pb_rpeer.PeerToRouter{
		ConnectionRequest: &pb_rpeer.ConnectionRequest{
			HostId: hostID,
		},
	}

	data, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	if err := routerClient.conn.WriteMessage(uint8(pb_peer.ChannelId_CHANNEL_ID_SESSION), data); err != nil {
		return nil, err
	}

	// 2. Wait for ConnectionOffer
	timeout := time.After(30 * time.Second)
	var offer *pb_rpeer.ConnectionOffer

	for {
		select {
		case <-timeout:
			return nil, errors.New("timeout waiting for connection offer")
		default:
			routerClient.conn.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			channelID, data, err := routerClient.conn.ReadMessage()
			routerClient.conn.conn.SetReadDeadline(time.Time{})

			if err != nil {
				return nil, err
			}

			if channelID == uint8(pb_peer.ChannelId_CHANNEL_ID_SESSION) {
				msg := &pb_rpeer.RouterToPeer{}
				if err := proto.Unmarshal(data, msg); err != nil {
					continue
				}

				if msg.ConnectionOffer != nil {
					offer = msg.ConnectionOffer
					goto OfferReceived
				}
				if msg.HostStatus != nil {
					if msg.HostStatus.Status == pb_rpeer.HostStatus_STATUS_OFFLINE {
						return nil, errors.New("host is offline")
					}
				}
			}
		}
	}

OfferReceived:
	DebugLog("[DEBUG] OfferReceived: ErrorCode=%v", offer.ErrorCode)
	if offer.ErrorCode != pb_rpeer.ConnectionOffer_SUCCESS {
		return nil, fmt.Errorf("connection offer failed: %v", offer.ErrorCode)
	}

	log.Printf("[DEBUG] Connecting to Relay: %s:%d", offer.Relay.Host, offer.Relay.Port)

	// 3. Connect to Relay
	relayConn, err := ConnectToRelay(offer.Relay.Host, int(offer.Relay.Port), offer.Relay.Key, string(offer.Relay.Secret))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay: %w", err)
	}
	defer relayConn.Close()

	// 4. Authenticate with Host (SRP)
	// Use provided host credentials if available, otherwise fallback to router credentials (unlikely to work but keeps old behavior as fallback)
	u := hostUsername
	p := hostPassword
	if u == "" {
		u = c.username
	}
	if p == "" {
		p = c.password
	}

	hostClient := &Client{
		conn:     NewConnection(relayConn),
		username: u,
		password: p,
	}

	if err := hostClient.authenticate(pb_router.SessionType(pb_peer.SessionType_SESSION_TYPE_SYSTEM_INFO)); err != nil {
		return nil, fmt.Errorf("host authentication failed: %w", err)
	}

	// Debug: Check if connection is still alive or if server sent something
	hostClient.conn.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	chID, data, err := hostClient.conn.ReadMessage()
	hostClient.conn.conn.SetReadDeadline(time.Time{})
	if err == nil {
		DebugLog("[DEBUG] Received unexpected message after handshake: ch=%d, len=%d, data=%x", chID, len(data), data)
	} else {
		DebugLog("[DEBUG] No message after handshake (err: %v)", err)
	}

	finalSysInfo := &pb_sys.SystemInfo{}

	// If no categories provided, default to Summary
	if len(categories) == 0 {
		categories = []string{SystemInfoSummary}
	}

	// 5. Check version and decide on pipelining
	usePipelining := true
	if hostClient.ProtocolVersion != nil {
		if hostClient.ProtocolVersion.Major < 2 || (hostClient.ProtocolVersion.Major == 2 && hostClient.ProtocolVersion.Minor < 6) {
			usePipelining = false
			log.Printf("[DEBUG] Detected older Aspia version (%d.%d.%d), disabling pipelining",
				hostClient.ProtocolVersion.Major, hostClient.ProtocolVersion.Minor, hostClient.ProtocolVersion.Patch)
		}
	}

	if usePipelining {
		// Pipelined approach (Fast)
		log.Printf("[DEBUG] Pipelining %d system info requests...", len(categories))
		for _, category := range categories {
			DebugLog("[DEBUG] Requesting category: %s", category)

			// Send SystemInfoRequest
			sysReq := &pb_sys.SystemInfoRequest{
				Category: category,
			}

			reqBytes, err := proto.Marshal(sysReq)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal system info request: %w", err)
			}

			// Send on Channel 0 (Session)
			if err := hostClient.conn.WriteMessage(0, reqBytes); err != nil {
				return nil, fmt.Errorf("failed to send system info request: %w", err)
			}
		}

		// Read all responses
		expectedResponses := len(categories)
		receivedResponses := 0

		// Map to track which categories we've received to avoid duplicates or confusion
		receivedCategories := make(map[string]bool)

		// Set a total timeout for all responses
		totalTimeout := time.After(30 * time.Second)

		for receivedResponses < expectedResponses {
			select {
			case <-totalTimeout:
				log.Printf("[WARN] Timeout waiting for system info responses. Received %d/%d", receivedResponses, expectedResponses)
				return finalSysInfo, nil // Return what we have
			default:
				// Read next message
				hostClient.conn.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				channelID, data, err := hostClient.conn.ReadMessage()
				hostClient.conn.conn.SetReadDeadline(time.Time{})

				if err != nil {
					log.Printf("[ERROR] Failed to read message: %v", err)
					// If connection is broken, we can't read anymore
					return finalSysInfo, nil
				}

				if len(data) == 0 {
					DebugLog("[DEBUG] Received empty message (KeepAlive?), ignoring...")
					continue
				}

				DebugLog("[DEBUG] ReadMessage returned channelID=%d, dataLen=%d", channelID, len(data))

				if channelID == uint8(pb_peer.ChannelId_CHANNEL_ID_SESSION) {
					sysInfo := &pb_sys.SystemInfo{}
					if err := proto.Unmarshal(data, sysInfo); err != nil {
						log.Printf("[ERROR] Failed to unmarshal SystemInfo: %v", err)
						continue
					}

					category := sysInfo.GetFooter().GetCategory()
					if category != "" {
						if !receivedCategories[category] {
							DebugLog("[DEBUG] Received SystemInfo for category %s", category)
							proto.Merge(finalSysInfo, sysInfo)
							receivedCategories[category] = true
							receivedResponses++
						} else {
							DebugLog("[DEBUG] Duplicate response for category %s, ignoring...", category)
						}
					} else {
						DebugLog("[DEBUG] Received SystemInfo without category footer, merging anyway...")
						proto.Merge(finalSysInfo, sysInfo)
						receivedResponses++
					}
				}
			}
		}
	} else {
		// Sequential approach (Slow but safe for older agents)
		log.Printf("[DEBUG] Using sequential system info retrieval for older agent...")

		// Give agent time to initialize after handshake
		time.Sleep(1 * time.Second)

		for _, category := range categories {
			DebugLog("[DEBUG] Requesting category: %s", category)

			// Send SystemInfoRequest
			sysReq := &pb_sys.SystemInfoRequest{
				Category: category,
			}

			reqBytes, err := proto.Marshal(sysReq)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal system info request: %w", err)
			}

			// Send on Channel 0 (Session)
			if err := hostClient.conn.WriteMessage(0, reqBytes); err != nil {
				return nil, fmt.Errorf("failed to send system info request: %w", err)
			}

			// Wait for response
			hostClient.conn.conn.SetReadDeadline(time.Now().Add(5 * time.Second))

			// Loop to handle potential KeepAlives or other messages
			for {
				channelID, data, err := hostClient.conn.ReadMessage()
				if err != nil {
					log.Printf("[ERROR] Failed to read message for category %s: %v", category, err)
					break // Move to next category
				}

				if len(data) == 0 {
					continue
				}

				if channelID == uint8(pb_peer.ChannelId_CHANNEL_ID_SESSION) {
					sysInfo := &pb_sys.SystemInfo{}
					if err := proto.Unmarshal(data, sysInfo); err != nil {
						log.Printf("[ERROR] Failed to unmarshal SystemInfo: %v", err)
						continue
					}
					proto.Merge(finalSysInfo, sysInfo)
					break // Success, move to next category
				}
			}
			hostClient.conn.conn.SetReadDeadline(time.Time{})

			// Small delay to be safe
			time.Sleep(50 * time.Millisecond)
		}
	}

	return finalSysInfo, nil
}
