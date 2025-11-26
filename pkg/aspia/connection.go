package aspia

import (
	"errors"
	"fmt"
	"io"
	"net"

	"google.golang.org/protobuf/proto"

	"aspia_rest_api/pkg/aspia/crypto"
)

const (
	MaxMessageSize = 7 * 1024 * 1024 // 7 MB
)

type Connection struct {
	conn      net.Conn
	encryptor crypto.Encryptor
	decryptor crypto.Decryptor

	// Channel ID support is negotiated during handshake
	ChannelIdSupported bool
	// HeaderEncrypted determines if the Channel ID header is part of the encrypted payload
	HeaderEncrypted bool
}

func NewConnection(conn net.Conn) *Connection {
	return &Connection{
		conn: conn,
	}
}

func (c *Connection) SetEncryption(encryptor crypto.Encryptor, decryptor crypto.Decryptor) {
	c.encryptor = encryptor
	c.decryptor = decryptor
}

func (c *Connection) Close() error {
	return c.conn.Close()
}

func (c *Connection) WriteMessage(channelID uint8, data []byte) error {
	var payload []byte

	if c.HeaderEncrypted {
		// Encrypted Header: [ChannelID][Reserved][Data] -> Encrypt -> [Size][Ciphertext]
		if c.ChannelIdSupported {
			header := []byte{channelID, 0} // channel_id, reserved
			payload = append(header, data...)
		} else {
			payload = data
		}

		if c.encryptor != nil {
			var err error
			payload, err = c.encryptor.Encrypt(payload)
			if err != nil {
				return fmt.Errorf("encryption failed: %w", err)
			}
		}
	} else {
		// Plaintext Header: [ChannelID][Reserved][Encrypt(Data)] -> [Size][Header][Ciphertext]
		// Wait, my previous logic was: [Size][Header][Encrypt(Data)]
		// Let's stick to what worked for Router/Host40.

		if c.encryptor != nil {
			var err error
			payload, err = c.encryptor.Encrypt(data)
			if err != nil {
				return fmt.Errorf("encryption failed: %w", err)
			}
		} else {
			payload = data
		}

		if c.ChannelIdSupported {
			header := []byte{channelID, 0} // channel_id, reserved
			payload = append(header, payload...)
		}
	}

	// 3. Prepend Size
	size := len(payload)
	if size > MaxMessageSize {
		return fmt.Errorf("message too large: %d", size)
	}

	sizeBytes := encodeVariableSize(size)

	// 4. Write
	toSend := append(sizeBytes, payload...)
	DebugLog("[SEND] Total %d bytes: %x", len(toSend), toSend)
	_, err := c.conn.Write(toSend)
	return err
}

func (c *Connection) ReadMessage() (uint8, []byte, error) {
	// 1. Read Size
	size, err := c.readVariableSize()
	if err != nil {
		return 0, nil, err
	}

	if size > MaxMessageSize {
		return 0, nil, fmt.Errorf("message too large: %d", size)
	}

	if size == 0 {
		return 0, nil, nil
	}

	// 2. Read Body
	body := make([]byte, size)
	_, err = io.ReadFull(c.conn, body)
	if err != nil {
		return 0, nil, err
	}
	DebugLog("[RECV] Total %d bytes (size=%d): %x", len(body)+len([]byte{byte(size)}), size, body)

	var channelID uint8

	if c.HeaderEncrypted {
		// Decrypt first, then extract header
		if c.decryptor != nil {
			overhead := c.decryptor.Overhead()
			if len(body) < overhead {
				DebugLog("[WARN] Received message smaller than encryption overhead (%d < %d), ignoring...", len(body), overhead)
				return 0, nil, nil
			}

			var err error
			body, err = c.decryptor.Decrypt(body)
			if err != nil {
				return 0, nil, fmt.Errorf("decryption failed: %w", err)
			}
			DebugLog("[DEBUG] Decrypted body (len=%d): %x", len(body), body[:min(32, len(body))])
		}

		if c.ChannelIdSupported {
			if len(body) < 2 {
				return 0, nil, errors.New("message too short for header")
			}
			channelID = body[0]
			// reserved = body[1]
			body = body[2:]
		}
	} else {
		// Extract header first, then decrypt
		if c.ChannelIdSupported {
			if len(body) < 2 {
				// If message is too short for header, it's definitely not a valid packet if we expect a header.
				// However, if it's a KeepAlive (size=1?), we might want to ignore it too?
				// But for now, let's stick to the error or ignore if it's really small?
				// If size=1, body=01.
				DebugLog("[WARN] Message too short for header (len=%d), ignoring...", len(body))
				return 0, nil, nil
			}
			channelID = body[0]
			// reserved = body[1]
			body = body[2:]
		}

		if c.decryptor != nil {
			overhead := c.decryptor.Overhead()
			if len(body) < overhead {
				DebugLog("[WARN] Received message smaller than encryption overhead (%d < %d), ignoring...", len(body), overhead)
				return 0, nil, nil
			}

			var err error
			body, err = c.decryptor.Decrypt(body)
			if err != nil {
				return 0, nil, fmt.Errorf("decryption failed: %w", err)
			}
			DebugLog("[DEBUG] Decrypted body (len=%d): %x", len(body), body[:min(32, len(body))])
		}
	}

	return channelID, body, nil
}

// ReadMessageProto reads a message and unmarshals it into the provided protobuf message
func (c *Connection) ReadMessageProto(msg proto.Message) error {
	_, data, err := c.ReadMessage()
	if err != nil {
		return err
	}
	return proto.Unmarshal(data, msg)
}

func encodeVariableSize(size int) []byte {
	// Logic from variable_size.cc
	// 1 byte: 0xxxxxxx (0-127)
	// 2 bytes: 1xxxxxxx 0xxxxxxx (128-16383)
	// 3 bytes: 1xxxxxxx 1xxxxxxx xxxxxxxx (16384-2097151)

	if size <= 0x7F {
		return []byte{uint8(size)}
	} else if size <= 0x3FFF {
		return []byte{
			uint8(size&0x7F | 0x80),
			uint8(size >> 7),
		}
	} else {
		return []byte{
			uint8(size&0x7F | 0x80),
			uint8((size>>7)&0x7F | 0x80),
			uint8(size >> 14),
		}
	}
}

func (c *Connection) readVariableSize() (int, error) {
	b := make([]byte, 1)

	// Read 1st byte
	if _, err := io.ReadFull(c.conn, b); err != nil {
		return 0, err
	}

	if b[0]&0x80 == 0 {
		return int(b[0]), nil
	}

	result := int(b[0] & 0x7F)

	// Read 2nd byte
	if _, err := io.ReadFull(c.conn, b); err != nil {
		return 0, err
	}

	if b[0]&0x80 == 0 {
		result += int(b[0]) << 7
		return result, nil
	}

	result += int(b[0]&0x7F) << 7

	// Read 3rd byte
	if _, err := io.ReadFull(c.conn, b); err != nil {
		return 0, err
	}

	if b[0]&0x80 == 0 {
		result += int(b[0]) << 14
		return result, nil
	}

	result += int(b[0]&0x7F) << 14

	// Read 4th byte
	if _, err := io.ReadFull(c.conn, b); err != nil {
		return 0, err
	}

	result += int(b[0]) << 21
	return result, nil
}
