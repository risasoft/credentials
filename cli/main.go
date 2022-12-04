package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Rocket-Pool-Rescue-Node/credentials"
	"google.golang.org/protobuf/proto"
)

const timestampFormat = "Mon 02 Jan 2006 3:04:05 PM MST"

func main() {

	nodeAddrFlag := flag.String("n", "", "Node address for which to generate the credential (required)")
	timeFlag := flag.String("t", time.Now().Format(timestampFormat), "Timestamp to use")
	secretFlag := flag.String("s", "test-secret", "Secret to use")

	flag.Parse()

	if *nodeAddrFlag == "" {
		fmt.Println("Usage: cred-cli [OPTIONS]")
		flag.PrintDefaults()
		os.Exit(1)
		return
	}

	cm := credentials.NewCredentialManager(sha256.New, []byte(*secretFlag))

	nodeID, err := hex.DecodeString(strings.TrimPrefix(*nodeAddrFlag, "0x"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
		return
	}

	t, err := time.Parse(timestampFormat, *timeFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
		return
	}

	cred, err := cm.Create(t, nodeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
		return
	}

	cred.Credential.NodeId = nil

	marshaled, err := proto.Marshal(cred)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
		return
	}

	var encoded bytes.Buffer
	encoder := base64.NewEncoder(base64.URLEncoding, &encoded)
	encoder.Write(marshaled)
	encoder.Close()

	password := string(encoded.Bytes())

	encoded.Reset()
	encoder = base64.NewEncoder(base64.URLEncoding, &encoded)
	encoder.Write(nodeID)
	encoder.Close()

	username := string(encoded.Bytes())
	fmt.Printf("%s:%s\n", username, password)
}
