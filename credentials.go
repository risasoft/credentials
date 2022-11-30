package credentials

import (
	"crypto/hmac"
	"fmt"
	"hash"
	"time"

	"github.com/Rocket-Pool-Rescue-Node/credentials/pb"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

type CredentialManager struct {
	hmac hash.Hash
}

// NewCrednetialManager creates a new CredentialManager which can create and verify signed credentials
func NewCredentialManager(h func() hash.Hash, key []byte) *CredentialManager {
	return &CredentialManager{
		hmac.New(h, key),
	}
}

func (c *CredentialManager) signCredential(credential *pb.SignedCredential) error {
	// Serialize just the inner message so we can sign it and add it to the outer message
	bytes, err := proto.Marshal(credential.Credential)
	if err != nil {
		return errors.Wrap(err, "Error serializing HMAC protobuf body")
	}

	c.hmac.Write(bytes)
	credential.Signature = c.hmac.Sum(nil)
	c.hmac.Reset()

	return nil
}

// Create makes a new credential and signs it, returning a protoc struct that can be marshaled/unmarshaled
func (c *CredentialManager) Create(timestamp time.Time, nodeId []byte) (*pb.SignedCredential, error) {
	if len(nodeId) != 20 {
		return nil, fmt.Errorf("Invalid nodeId length. Expected 20, got %d\n", len(nodeId))
	}
	message := pb.SignedCredential{}
	message.Credential = &pb.Credential{}
	message.Credential.NodeId = nodeId
	message.Credential.Timestamp = timestamp.Unix()

	if err := c.signCredential(&message); err != nil {
		return nil, err
	}

	return &message, nil
}

// Verify checks that a SignedCredential has a valid signature
func (c *CredentialManager) Verify(signedCredential *pb.SignedCredential) error {
	// Create a temporary SignedCredential and borrow the inner message from the provided credential
	tmp := pb.SignedCredential{}
	tmp.Credential = signedCredential.Credential

	// Sign tmp
	if err := c.signCredential(&tmp); err != nil {
		return errors.Wrap(err, "Error while re-creating the signature")
	}

	// Check that tmp's signature matches the provided one.
	if hmac.Equal(tmp.Signature, signedCredential.Signature) == false {
		// Signatures didn't match. Authenticity cannot be verified.
		return errors.New("Credential signature mismatch.")
	}

	return nil
}
