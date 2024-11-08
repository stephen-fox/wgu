package wgkeys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
)

func NewNoisePrivateKey() (*device.NoisePrivateKey, error) {
	b := make([]byte, device.NoisePrivateKeySize)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	private := &device.NoisePrivateKey{}
	copy(private[:], b)
	return private, nil
}

func NoisePublicKeyFromPrivate(private *device.NoisePrivateKey) *device.NoisePublicKey {
	public := &device.NoisePublicKey{}
	apk := (*[device.NoisePublicKeySize]byte)(public)
	ask := (*[device.NoisePrivateKeySize]byte)(private)
	curve25519.ScalarBaseMult(apk, ask)
	return public
}

func NoisePrivateKeyFromBase64(b64 string) (*device.NoisePrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	return NoisePrivateKeyFromBytes(b)
}

func NoisePrivateKeyFromBytes(b []byte) (*device.NoisePrivateKey, error) {
	if len(b) != device.NoisePrivateKeySize {
		return nil, fmt.Errorf("key bytes has incorrect number of bytes (%d), expected: %d",
			len(b), device.NoisePrivateKeySize)
	}

	private := &device.NoisePrivateKey{}
	copy(private[:], b)
	return private, nil
}

func NoisePublicKeyFromBase64(b64 string) (*device.NoisePublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	return NoisePublicKeyFromBytes(b)
}

func NoisePublicKeyFromBytes(b []byte) (*device.NoisePublicKey, error) {
	if len(b) != device.NoisePublicKeySize {
		return nil, fmt.Errorf("got incorrect number of bytes (%d), expected: %d",
			len(b), device.NoisePublicKeySize)
	}

	public := &device.NoisePublicKey{}
	copy(public[:], b)
	return public, nil
}
