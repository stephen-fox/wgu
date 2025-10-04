package wgkeys

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
)

func NoisePrivateKeyToPublicDisplayString(private *device.NoisePrivateKey) string {
	pub := NoisePublicKeyFromPrivate(private)

	return NoisePublicKeyToString(pub)
}

func NoisePublicKeyToDisplayString(pub *device.NoisePublicKey) string {
	return NoisePublicKeyToString(pub)
}

func NoisePublicKeyToString(pub *device.NoisePublicKey) string {
	return base64.StdEncoding.EncodeToString(pub[:])
}

func NoisePublicKeyFromPrivate(private *device.NoisePrivateKey) *device.NoisePublicKey {
	public := &device.NoisePublicKey{}
	apk := (*[device.NoisePublicKeySize]byte)(public)
	ask := (*[device.NoisePrivateKeySize]byte)(private)
	curve25519.ScalarBaseMult(apk, ask)
	return public
}

func NoisePublicKeyFromBase64(b64 string) (*device.NoisePublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	return NoisePublicKeyFromBase64Bytes(b)
}

func NoisePublicKeyFromBase64Bytes(b []byte) (*device.NoisePublicKey, error) {
	if len(b) != device.NoisePublicKeySize {
		return nil, fmt.Errorf("got incorrect number of bytes (%d), expected: %d",
			len(b), device.NoisePublicKeySize)
	}

	public := &device.NoisePublicKey{}
	copy(public[:], b)
	return public, nil
}
