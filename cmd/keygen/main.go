package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

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

// readScalarFromFile reads the scalar from a file
func readScalarFromFile(filename string) (*ristretto.Scalar, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var scalar ristretto.Scalar
	_, err = scalar.SetBytesWithClamping(data)
	if err != nil {
		return nil, err
	}
	return &scalar, nil
}

// Initialize participant for key generation round 1
func initParticipant(id party.ID, n, t party.Size, outputFile, stateFile string) {
	msg, state, err := messages.Round0(id, n, t)
	if err != nil {
		fmt.Println("Error initializing participant:", err)
		return
	}

	data, _ := msg.MarshalJSON()
	writeFile(outputFile, data)

	stateData, _ := state.MarshalJSON()
	writeFile(stateFile, stateData)
}

// Key generation round 1
func keyGenRound1(state *messages.State, inputFiles []string, outputFile, stateFile string) {
	msgs := make([]*messages.Message, len(inputFiles))
	for i, file := range inputFiles {
		data, _ := readFile(file)
		var msg messages.Message
		msg.UnmarshalJSON(data)
		msgs[i] = &msg
	}

	outMsgs, secret, state, err := messages.Round1(state, msgs)
	if err != nil {
		fmt.Println("Error in key generation round 1:", err)
		return
	}

	// Write output messages to files
	for _, outMsg := range outMsgs {
		data, _ := outMsg.MarshalJSON()
		writeFile(fmt.Sprintf("round1_out_%d_%d.json", outMsg.From, outMsg.To), data)
	}

	// Save secret to file
	writeFile(outputFile, secret.Bytes())

	stateData, _ := state.MarshalJSON()
	writeFile(stateFile, stateData)
}

// Key generation round 2
func keyGenRound2(state *messages.State, inputFiles []string, secretFile string, outputFile string) {
	msgs := make([]*messages.Message, len(inputFiles))
	for i, file := range inputFiles {
		data, _ := readFile(file)
		var msg messages.Message
		msg.UnmarshalJSON(data)
		msgs[i] = &msg
	}

	secret, err := readScalarFromFile(secretFile)
	if err != nil {
		fmt.Println("Error reading secret from file:", err)
		return
	}

	pub, sec, err := messages.Round2(state, msgs, secret)
	if err != nil {
		fmt.Println("Error in key generation round 2:", err)
		return
	}

	// Write public and secret keys to files
	pubData, _ := pub.MarshalJSON()
	writeFile(outputFile+"_pub.json", pubData)

	secData, _ := sec.MarshalBinary()
	writeFile(outputFile+"_sec.dat", secData)
}
func main() {
	var (
		id         = flag.Int("id", 0, "Participant ID")
		n          = flag.Int("n", 0, "Number of participants")
		t          = flag.Int("t", 0, "Threshold")
		init       = flag.Bool("init", false, "Initialize participant")
		round1     = flag.Bool("round1", false, "Execute key generation round 1")
		round2     = flag.Bool("round2", false, "Execute key generation round 2")
		inputFiles = flag.String("input", "", "Comma-separated list of input files")
		outputFile = flag.String("output", "", "Output file")
		secretFile = flag.String("secret", "", "Secret file for round 2")
		stateFile  = flag.String("state", "", "State file")
	)

	flag.Parse()

	if *id == 0 || *outputFile == "" {
		fmt.Println("Participant ID and output file are required")
		return
	}

	if *stateFile == "" {
		fmt.Println("State file is required")
		return
	}

	if (*n == 0 || *t == 0) && *init {
		fmt.Println("Number of participants and threshold are required for initialization")
		return
	}

	participantID := party.ID(*id)
	N := party.Size(*n)
	T := party.Size(*t)

	if *init {
		initParticipant(participantID, N, T, *outputFile, *stateFile)
	} else if *round1 {
		if *inputFiles == "" {
			fmt.Println("Input files are required for round 1")
			return
		}
		files := strings.Split(*inputFiles, ",")

		stateData, _ := readFile(*stateFile)
		var state messages.State
		state.UnmarshalJSON(stateData)

		keyGenRound1(&state, files, *outputFile, *stateFile)
	} else if *round2 {
		if *inputFiles == "" || *secretFile == "" {
			fmt.Println("Input files and secret file are required for round 2")
			return
		}
		files := strings.Split(*inputFiles, ",")

		stateData, _ := readFile(*stateFile)
		var state messages.State
		state.UnmarshalJSON(stateData)

		keyGenRound2(&state, files, *secretFile, *outputFile)
	} else {
		fmt.Println("Specify --init, --round1, or --round2")
	}
}
