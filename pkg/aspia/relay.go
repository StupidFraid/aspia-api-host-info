package aspia

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"google.golang.org/protobuf/proto"

	"aspia_rest_api/pkg/aspia/crypto"

	pb_relay "aspia_rest_api/proto/relay_peer"
	pb_router "aspia_rest_api/proto/router"
)

func ConnectToRelay(host string, port int, key *pb_router.RelayKey, secret string) (net.Conn, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// 1. Generate Ephemeral Key Pair
	keyPair, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 2. Calculate Shared Secret
	peerPublicKey := key.PublicKey
	sharedSecret, err := keyPair.SharedSecret(peerPublicKey)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 3. Derive Session Key (BLAKE2s256)
	sessionKey := crypto.HashBlake2s256(sharedSecret)

	// 4. Encrypt Secret
	iv := key.Iv
	encryptor, err := crypto.NewChaCha20Poly1305Encryptor(sessionKey, iv)
	if err != nil {
		conn.Close()
		return nil, err
	}

	encryptedSecret, err := encryptor.Encrypt([]byte(secret))
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 5. Create PeerToRelay Message
	msg := &pb_relay.PeerToRelay{
		KeyId:     key.KeyId,
		PublicKey: keyPair.PublicKey,
		Data:      encryptedSecret,
	}

	data, err := proto.Marshal(msg)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 6. Send Message (Size + Data)
	// RelayPeer::onConnected sends size as BigEndian uint32
	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(len(data)))

	if _, err := conn.Write(sizeBuf); err != nil {
		conn.Close()
		return nil, err
	}

	if _, err := conn.Write(data); err != nil {
		conn.Close()
		return nil, err
	}

	// 7. Return Connection
	// The connection is now a tunnel to the host.
	return conn, nil
}
