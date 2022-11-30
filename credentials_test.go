package credentials

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"github.com/Rocket-Pool-Rescue-Node/credentials/pb"
	"google.golang.org/protobuf/proto"
)

// TestCredentialRoundTrip creates, signs, marshals, encodes, decodes, unmarshals, and verifies a credential
func TestCredentialRoundTrip(t *testing.T) {
	cm := NewCredentialManager(sha1.New, []byte("Curiouser and curiouser"))

	nodeId, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeId)
	if err != nil {
		t.Error(err)
	}

	marshaled, err := proto.Marshal(cred)
	if err != nil {
		t.Error(err)
	}

	t.Logf("Marshaled proto: %x\n", marshaled)

	var encoded bytes.Buffer
	encoder := base64.NewEncoder(base64.URLEncoding, &encoded)
	encoder.Write(marshaled)
	encoder.Close()
	t.Logf("b64 encoded proto: %s\n", string(encoded.Bytes()))

	// Now to reverse the process
	decoder := base64.NewDecoder(base64.URLEncoding, bytes.NewReader(encoded.Bytes()))
	decoded, err := io.ReadAll(decoder)
	t.Logf("b64 decoded proto: %x\n", decoded)
	if err != nil {
		t.Error(err)
	}

	unmarshaled := &pb.SignedCredential{}
	err = proto.Unmarshal(decoded, unmarshaled)
	if err != nil {
		t.Error(err)
	}

	err = cm.Verify(unmarshaled)
	if err != nil {
		t.Error(err)
	}

	// Finally, do some sanity checks
	if bytes.Compare(unmarshaled.Credential.NodeId, cred.Credential.NodeId) != 0 {
		t.Fail()
	}

	if unmarshaled.Credential.Timestamp != cred.Credential.Timestamp {
		t.Fail()
	}
}

// TestCredentialStolenSignature creates 2 signed credentials, swaps their signatures, and ensures that they don't pass Verify
func TestCredentialStolenSignature(t *testing.T) {
	cm := NewCredentialManager(sha1.New, []byte("We're all mad here"))

	nodeId, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeId)
	if err != nil {
		t.Error(err)
	}

	nodeId2, err := hex.DecodeString("2234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred2, err := cm.Create(time.Now(), nodeId2)
	if err != nil {
		t.Error(err)
	}

	// Swap signatures and make sure Verify returns an error
	cred.Signature, cred2.Signature = cred2.Signature, cred.Signature
	err = cm.Verify(cred)
	if err == nil {
		t.Fail()
	}
	err = cm.Verify(cred2)
	if err == nil {
		t.Fail()
	}

	// Swap back and make sure Verify now works
	cred.Signature, cred2.Signature = cred2.Signature, cred.Signature
	err = cm.Verify(cred)
	if err != nil {
		t.Error(err)
	}
	err = cm.Verify(cred2)
	if err != nil {
		t.Error(err)
	}
}

// TestHmacKey sanity-tests that a signature is only valid for a given key
func TestHmacKey(t *testing.T) {
	cm := NewCredentialManager(sha1.New, []byte("T'was brillig"))
	cm2 := NewCredentialManager(sha1.New, []byte("And the slithy toves did gyre"))

	nodeId, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeId)

	err = cm2.Verify(cred)
	if err == nil {
		t.Fail()
	}

	err = cm.Verify(cred)
	if err != nil {
		t.Error(err)
	}
}

// TestCredentialManagerReuse tests that subsequent calls to the same CredentialManager preduce predictable results
func TestCredentialManagerReuse(t *testing.T) {
	cm := NewCredentialManager(sha1.New, []byte("Off with their heads!"))

	nodeId, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeId)
	if err != nil {
		t.Error(err)
	}
	cred2, err := cm.Create(time.Now(), nodeId)
	if err != nil {
		t.Error(err)
	}

	err = cm.Verify(cred)
	if err != nil {
		t.Error(err)
	}

	err = cm.Verify(cred2)
	if err != nil {
		t.Error(err)
	}
}
