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

// CredentialManager authenticates and verifies rescue node credentials
type CredentialManager struct {
	hash.Hash
}

// NewCredentialManager creates a new CredentialManager which can create and verify authenticated credentials
func NewCredentialManager(h func() hash.Hash, key []byte) *CredentialManager {
	return &CredentialManager{
		hmac.New(h, key),
	}
}

func (c *CredentialManager) authenticateCredential(credential *pb.AuthenticatedCredential) error {
	// Serialize just the inner message so we can authenticate it and add it to the outer message
	bytes, err := proto.Marshal(credential.Credential)
	if err != nil {
		return errors.Wrap(err, "Error serializing HMAC protobuf body")
	}

	c.Write(bytes)
	credential.Mac = c.Sum(nil)
	c.Reset()

	return nil
}

// Create makes a new credential and authenticates it, returning a protoc struct that can be marshaled/unmarshaled
func (c *CredentialManager) Create(timestamp time.Time, nodeID []byte) (*pb.AuthenticatedCredential, error) {
	if len(nodeID) != 20 {
		return nil, fmt.Errorf("invalid nodeID length. Expected 20, got %d", len(nodeID))
	}
	message := pb.AuthenticatedCredential{}
	message.Credential = &pb.Credential{}
	message.Credential.NodeId = nodeID
	message.Credential.Timestamp = timestamp.Unix()

	if err := c.authenticateCredential(&message); err != nil {
		return nil, err
	}

	return &message, nil
}

// Verify checks that a AuthenticatedCredential has a valid mac
func (c *CredentialManager) Verify(authenticatedCredential *pb.AuthenticatedCredential) error {
	// Create a temporary AuthenticatedCredential and borrow the inner message from the provided credential
	tmp := pb.AuthenticatedCredential{}
	tmp.Credential = authenticatedCredential.Credential

	// Auth tmp
	if err := c.authenticateCredential(&tmp); err != nil {
		return errors.Wrap(err, "Error while re-creating the MAC")
	}

	// Check that tmp's MAC matches the provided one.
	if hmac.Equal(tmp.Mac, authenticatedCredential.Mac) == false {
		// MAC didn't match. Authenticity cannot be verified.
		return errors.New("credential MAC mismatch")
	}

	return nil
}
