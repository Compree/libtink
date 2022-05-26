package libtink

import (
	"encoding/base64"
	"github.com/google/tink/go/aead"
	clearrw "github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"os"
)

// ReadKeysetHandle returns a pointer to handle to be used to create primitives.
// It takes the name of the handle file as a string.
func ReadKeysetHandle(dataFile string) (handle *keyset.Handle, err error) {
	r, err := os.Open(dataFile)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	br := keyset.NewBinaryReader(r)
	handle, err = clearrw.Read(br)
	return handle, err
}

// WriteKeysetHandle writes a handle file for use by ReadKeysetHandle later or elsewhere.
// It takes the name of the handle file as a string.
func WriteKeysetHandle(dataFile string) (err error) {
	handlep, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	w, err := os.Create(dataFile)
	if err != nil {
		return err
	}
	defer w.Close()
	bw := keyset.NewBinaryWriter(w)
	err = clearrw.Write(handlep, bw)
	return err
}

// NewPrimitive returns a primitive suitable for encryption and decryption.
// It takes a pointer to a handle. See ReadKeysetHandle.
func NewPrimitive(handle *keyset.Handle) (prim tink.AEAD, err error) {
	return aead.New(handle)
}

// PrimFromFile is a convenience method that returns a new primitive from a filename.
func PrimFromFile(dataFile string) (prim tink.AEAD, err error) {
	handle, err := ReadKeysetHandle(dataFile)
	if err != nil {
		return nil, err
	}
	return NewPrimitive(handle)
}

func DecryptBase64EncodedStringToBytes(prim tink.AEAD, b64String string) (plainBytes []byte, err error) {
    cipherBytes, err := base64.StdEncoding.DecodeString(b64String)
    if err != nil {
        return
    }
	aad := []byte("")
	return prim.Decrypt(cipherBytes, aad)
}

// DecryptBase64EncodedString uses a tink.AEAD primitive to return the decrpyted base64 input.
func DecryptBase64EncodedString(prim tink.AEAD, encstring string) (plainstring string, err error) {
	pt, err := DecryptBase64EncodedStringToBytes(prim, encstring)
	return string(pt), err
}

// EncryptStringToBase64String uses a tink.AEAD primitive to return the encrpyted base64 from string input.
func EncryptStringToBase64String(prim tink.AEAD, plainstring string) (cipherBase64 string, err error) {
	return EncryptBytesToBase64String(prim, []byte(plainstring))
}

// EncryptBytesToBase64String uses a tink.AEAD primitive to return the encrpyted base64 from []byte input.
func EncryptBytesToBase64String(prim tink.AEAD, plainbytes []byte) (cipherBase64 string, err error) {
	aad := []byte("")
	cipherByteSlice, err := prim.Encrypt(plainbytes, aad)
	if err != nil {
		return "", err
	}
	cipherBase64 = base64.StdEncoding.EncodeToString(cipherByteSlice)
	return
}
