package wgu

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

	private := &device.NoisePrivateKey{}
	copy(private[:], b)
	return private, nil
}

func NoisePublicKeyFromBase64(b64 string) (*device.NoisePublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	public := &device.NoisePublicKey{}
	copy(public[:], b)
	return public, nil
}
