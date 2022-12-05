package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Rocket-Pool-Rescue-Node/credentials"
	"google.golang.org/protobuf/proto"
)

const timestampFormat = "Mon 02 Jan 2006 3:04:05 PM MST"

func parseToJson(credential string) (string, error) {

	strs := strings.Split(credential, ":")
	if len(strs) != 2 {
		return "", fmt.Errorf("Invalid credential: %s\n", credential)
	}

	decoder := base64.NewDecoder(base64.URLEncoding, bytes.NewReader([]byte(strs[0])))
	nodeID, err := io.ReadAll(decoder)
	if err != nil {
		return "", err
	}

	decoder = base64.NewDecoder(base64.URLEncoding, bytes.NewReader([]byte(strs[1])))
	p, err := io.ReadAll(decoder)
	if err != nil {
		return "", err
	}

	ac := credentials.AuthenticatedCredential{}
	err = proto.Unmarshal(p, ac.Pb())
	if err != nil {
		return "", err
	}

	ac.Credential.NodeId = nodeID

	j, err := json.MarshalIndent(&ac, "", "    ")
	return string(j), err
}

func main() {

	nodeAddrFlag := flag.String("n", "", "Node address for which to generate the credential (required)")
	timeFlag := flag.String("t", time.Now().Format(timestampFormat), "Timestamp to use")
	secretFlag := flag.String("s", "test-secret", "Secret to use")
	outputJsonFlag := flag.Bool("j", false, "Whether or not to print the credential in human-readable json")
	parseToJsonFlag := flag.String("p", "", "Parses a credential and prints it in human-readable json")

	flag.Parse()

	if *parseToJsonFlag != "" {
		str, err := parseToJson(*parseToJsonFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
			return
		}
		fmt.Println(str)
		return
	}

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

	if *outputJsonFlag {
		j, err := json.MarshalIndent(cred, "", "    ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
			return
		}

		fmt.Println(string(j))
		return
	}

	cred.Credential.NodeId = nil

	marshaled, err := proto.Marshal(cred.Pb())
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
