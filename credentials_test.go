package credentials

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

// TestCredentialRoundTrip creates, anthenticates, marshals, encodes, decodes, unmarshals, and verifies a credential
func TestCredentialRoundTrip(t *testing.T) {
	cm := NewCredentialManager(sha1.New, []byte("Curiouser and curiouser"))

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeID)
	if err != nil {
		t.Error(err)
	}

	marshaled, err := proto.Marshal(cred.Pb())
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

	unmarshaled := &AuthenticatedCredential{}
	err = proto.Unmarshal(decoded, unmarshaled.Pb())
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

// TestCredentialStolenMac creates 2 authenticated credentials, swaps their MACs, and ensures that they don't pass Verify
func TestCredentialStolenMac(t *testing.T) {
	cm := NewCredentialManager(sha1.New, []byte("We're all mad here"))

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeID)
	if err != nil {
		t.Error(err)
	}

	nodeID2, err := hex.DecodeString("2234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred2, err := cm.Create(time.Now(), nodeID2)
	if err != nil {
		t.Error(err)
	}

	// Swap NACs and make sure Verify returns an error
	cred.Mac, cred2.Mac = cred2.Mac, cred.Mac
	err = cm.Verify(cred)
	if err == nil {
		t.Fail()
	}
	err = cm.Verify(cred2)
	if err == nil {
		t.Fail()
	}

	// Swap back and make sure Verify now works
	cred.Mac, cred2.Mac = cred2.Mac, cred.Mac
	err = cm.Verify(cred)
	if err != nil {
		t.Error(err)
	}
	err = cm.Verify(cred2)
	if err != nil {
		t.Error(err)
	}
}

// TestHmacKey sanity-tests that a MAC is only valid for a given key
func TestHmacKey(t *testing.T) {
	cm := NewCredentialManager(sha1.New, []byte("T'was brillig"))
	cm2 := NewCredentialManager(sha1.New, []byte("And the slithy toves did gyre"))

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeID)

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

	nodeID, err := hex.DecodeString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Error(err)
	}
	cred, err := cm.Create(time.Now(), nodeID)
	if err != nil {
		t.Error(err)
	}
	cred2, err := cm.Create(time.Now(), nodeID)
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
