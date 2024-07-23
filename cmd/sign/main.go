package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bartke/threshold-signatures-ed25519/eddsa"
	"github.com/bartke/threshold-signatures-ed25519/messages"
	"github.com/bartke/threshold-signatures-ed25519/party"
	"github.com/bartke/threshold-signatures-ed25519/ristretto"
)

// Function to write data to a file
func writeFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}

// Function to read data from a file
func readFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

// Initialize participant for signing round 0
func initSigner(id party.ID, signers party.IDSlice, secretFile, sharesFile, messageFile, outputFile, stateFile string) {
	secretData, err := readFile(secretFile)
	if err != nil {
		fmt.Println("Error reading secret:", err)
		return
	}
	var secret eddsa.SecretShare
	if err := secret.UnmarshalBinary(secretData); err != nil {
		fmt.Println("Error unmarshaling secret:", err)
		return
	}

	sharesData, err := readFile(sharesFile)
	if err != nil {
		fmt.Println("Error reading shares:", err)
		return
	}
	var shares struct {
		T        int               `json:"t"`
		GroupKey string            `json:"groupkey"`
		Shares   map[string]string `json:"shares"`
	}
	if err := json.Unmarshal(sharesData, &shares); err != nil {
		fmt.Println("Error unmarshaling shares:", err)
		return
	}

	message, err := readFile(messageFile)
	if err != nil {
		fmt.Println("Error reading message:", err)
		return
	}

	// Convert group key and shares to required format
	var groupKey ristretto.Element
	groupKeyBytes, err := base64.StdEncoding.DecodeString(shares.GroupKey)
	if err != nil {
		fmt.Println("Error decoding group key:", err)
		return
	}
	if _, err := groupKey.SetCanonicalBytes(groupKeyBytes); err != nil {
		fmt.Println("Error unmarshaling group key:", err)
		return
	}

	pub := eddsa.Public{
		Threshold: party.Size(shares.T),
		GroupKey:  eddsa.NewPublicKeyFromPoint(&groupKey),
		Shares:    make(map[party.ID]*ristretto.Element),
	}

	var parties party.IDSlice
	for idStr, partyStr := range shares.Shares {
		id, err := party.FromString(idStr)
		if err != nil {
			fmt.Println("Error parsing party ID:", err)
			return
		}

		parties = append(parties, id)

		shareBytes, err := base64.StdEncoding.DecodeString(partyStr)
		if err != nil {
			fmt.Println("Error decoding share:", err)
			return
		}
		var share ristretto.Element
		if _, err := share.SetCanonicalBytes(shareBytes); err != nil {
			fmt.Println("Error unmarshaling share:", err)
			return
		}
		pub.Shares[id] = &share
	}

	pub.PartyIDs = parties

	msg, state, err := messages.SignRound0(signers, &secret, &pub, message)
	if err != nil {
		fmt.Println("Error initializing signer:", err)
		return
	}

	msgData, _ := msg.MarshalJSON()
	writeFile(outputFile, msgData)

	stateData, _ := state.MarshalJSON()
	writeFile(stateFile, stateData)
}

// Signing round 1
func signRound1(state *messages.SignerState, inputFiles []string, outputFile, stateFile string) {
	msgs := make([]*messages.Message, len(inputFiles))
	for i, file := range inputFiles {
		data, _ := readFile(file)
		var msg messages.Message
		msg.UnmarshalJSON(data)
		msgs[i] = &msg
	}

	outMsg, state, err := messages.SignRound1(state, msgs)
	if err != nil {
		fmt.Println("Error in signing round 1:", err)
		return
	}

	// Write output message to file
	outMsgData, _ := outMsg.MarshalJSON()
	writeFile(outputFile, outMsgData)

	// Save state to file
	stateData, _ := state.MarshalJSON()
	writeFile(stateFile, stateData)
}

// Signing round 2
func signRound2(state *messages.SignerState, inputFiles []string, outputFile string) {
	msgs := make([]*messages.Message, len(inputFiles))
	for i, file := range inputFiles {
		data, _ := readFile(file)
		var msg messages.Message
		msg.UnmarshalJSON(data)
		msgs[i] = &msg
	}

	sig, state, err := messages.SignRound2(state, msgs)
	if err != nil {
		fmt.Println("Error in signing round 2:", err)
		return
	}

	// Write signature to file
	sigData, _ := sig.MarshalBinary()
	writeFile(outputFile, sigData)

	// Save state to file
	stateData, _ := state.MarshalJSON()
	writeFile(outputFile, stateData)
}

func main() {
	var (
		id          = flag.Int("id", 0, "Participant ID")
		signers     = flag.String("signers", "", "Comma-separated list of signer IDs")
		init        = flag.Bool("init", false, "Initialize signer")
		round1      = flag.Bool("round1", false, "Execute signing round 1")
		round2      = flag.Bool("round2", false, "Execute signing round 2")
		secretFile  = flag.String("secret", "", "Secret file")
		sharesFile  = flag.String("shares", "", "Shares file")
		messageFile = flag.String("message", "", "Message file")
		inputFiles  = flag.String("input", "", "Comma-separated list of input files")
		outputFile  = flag.String("output", "", "Output file")
		stateFile   = flag.String("state", "", "State file")
	)

	flag.Parse()

	if *id == 0 || *outputFile == "" {
		fmt.Println("Participant ID and output file are required")
		return
	}

	if *signers == "" && *init {
		fmt.Println("Signers are required for initialization")
		return
	}

	participantID := party.ID(*id)

	if *init {
		if *secretFile == "" || *sharesFile == "" || *messageFile == "" {
			fmt.Println("Secret file, shares file, and message file are required for initialization")
			return
		}

		var signerIDs party.IDSlice
		for _, id := range strings.Split(*signers, ",") {
			partyID, err := party.FromString(id)
			if err != nil {
				fmt.Println("Error parsing party ID:", err)
				return
			}

			signerIDs = append(signerIDs, partyID)
		}

		initSigner(participantID, signerIDs, *secretFile, *sharesFile, *messageFile, *outputFile, *stateFile)
	} else if *round1 {
		if *inputFiles == "" || *stateFile == "" {
			fmt.Println("Input files and state file are required for round 1")
			return
		}
		files := strings.Split(*inputFiles, ",")

		stateData, _ := readFile(*stateFile)
		var state messages.SignerState
		state.UnmarshalJSON(stateData)

		signRound1(&state, files, *outputFile, *stateFile)
	} else if *round2 {
		if *inputFiles == "" || *stateFile == "" {
			fmt.Println("Input files and state file are required for round 2")
			return
		}
		files := strings.Split(*inputFiles, ",")

		stateData, _ := readFile(*stateFile)
		var state messages.SignerState
		state.UnmarshalJSON(stateData)

		signRound2(&state, files, *outputFile)
	} else {
		fmt.Println("Specify --init, --round1, or --round2")
	}
}
