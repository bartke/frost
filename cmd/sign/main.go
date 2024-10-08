package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bartke/frost"
	"github.com/bartke/frost/eddsa"
	"github.com/bartke/frost/party"
)

func writeFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}

func readFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

func initSigner(signers party.IDSlice, secretFile, sharesFile, messageFile, outputFile, stateFile string) {
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

	var shares eddsa.Public
	if err := json.Unmarshal(sharesData, &shares); err != nil {
		fmt.Println("Error unmarshaling shares:", err)
		return
	}

	message, err := readFile(messageFile)
	if err != nil {
		fmt.Println("Error reading message:", err)
		return
	}

	msg, state, err := frost.SignInit(signers, &secret, &shares, message)
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
func signRound1(state *frost.SignerState, inputFiles []string, outputFile, stateFile string) {
	msgs := make([]*frost.Message, len(inputFiles))
	for i, file := range inputFiles {
		data, _ := readFile(file)
		var msg frost.Message
		msg.UnmarshalJSON(data)
		msgs[i] = &msg
	}

	outMsg, state, err := frost.SignRound1(state, msgs)
	if err != nil {
		fmt.Println("Error in signing round 1:", err)
		return
	}

	// Write output message to file
	outMsgData, _ := outMsg.MarshalJSON()
	writeFile(outputFile, outMsgData)

	// Save state to file
	stateData, err := state.MarshalJSON()
	if err != nil {
		fmt.Println("Error marshaling state:", err)
		return
	}
	writeFile(stateFile, stateData)
}

// Signing round 2
func signRound2(state *frost.SignerState, inputFiles []string, outputFile string) {
	msgs := make([]*frost.Message, len(inputFiles))
	for i, file := range inputFiles {
		data, _ := readFile(file)
		var msg frost.Message
		msg.UnmarshalJSON(data)
		msgs[i] = &msg
	}

	sig, state, err := frost.SignRound2(state, msgs)
	if err != nil {
		fmt.Println("Error in signing round 2:", err)
		return
	}

	// verify also with the standard ed25519 library
	pubkey := state.GroupKey.ToEd25519()
	signature := sig.ToEd25519()
	// print hex
	if !ed25519.Verify(pubkey, state.Message, signature) {
		panic(errors.New("ed25519: full signature is invalid"))
	}

	fmt.Printf("Public key: %x\n", pubkey)
	fmt.Printf("Validated Signature: %x\n", signature)

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

	if *id == 0 && !*init || *outputFile == "" {
		fmt.Println("Participant ID and output file are required")
		return
	}

	if *signers == "" && *init {
		fmt.Println("Signers are required for initialization")
		return
	}

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

		initSigner(signerIDs, *secretFile, *sharesFile, *messageFile, *outputFile, *stateFile)
	} else if *round1 {
		if *inputFiles == "" || *stateFile == "" {
			fmt.Println("Input files and state file are required for round 1")
			return
		}
		files := strings.Split(*inputFiles, ",")

		stateData, _ := readFile(*stateFile)
		var state frost.SignerState
		if err := state.UnmarshalJSON(stateData); err != nil {
			fmt.Println("Error unmarshaling state:", err)
			return
		}

		signRound1(&state, files, *outputFile, *stateFile)
	} else if *round2 {
		if *inputFiles == "" || *stateFile == "" {
			fmt.Println("Input files and state file are required for round 2")
			return
		}
		files := strings.Split(*inputFiles, ",")

		stateData, _ := readFile(*stateFile)
		var state frost.SignerState
		if err := state.UnmarshalJSON(stateData); err != nil {
			fmt.Println("Error unmarshaling state:", err)
			return
		}

		signRound2(&state, files, *outputFile)
	} else {
		fmt.Println("Specify --init, --round1, or --round2")
	}
}
