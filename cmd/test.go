package main

import (
	"flag"
	"fmt"
	"os"
	"sdtl"
)

func main() {
	// Define the --out argument to specify the base name of the files
	out := flag.String("out", "sdtl", "Base name for the output files (default: 'sdtl')")
	showHelp := flag.Bool("help", false, "Show help message")

	// Parse command-line flags
	flag.Parse()

	// Show help and header if --help is passed or no arguments are provided
	if *showHelp {
		fmt.Printf("Key Gen SDTL - Protocol version: %x\n", sdtl.ProtocolVer)
		fmt.Println("Copyright 2024 Emiliano A. Billi")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Generate the private key
	pk, err := sdtl.GenerateKey()
	if err != nil {
		fmt.Printf("Error generating private key: %v\n", err)
		os.Exit(1)
	}

	// Serialize the private and public keys
	prikey, err := sdtl.MarshalECDSAPrivateKey(pk)
	if err != nil {
		fmt.Printf("Error serializing private key: %v\n", err)
		os.Exit(1)
	}

	pubkey, err := sdtl.MarshalECDSAPublicKey(&pk.PublicKey)
	if err != nil {
		fmt.Printf("Error serializing public key: %v\n", err)
		os.Exit(1)
	}

	// Create and write the private key to <out>_private.pem
	privateFile := *out + "_private.pem"
	fdPrivate, err := os.Create(privateFile)
	if err != nil {
		fmt.Printf("Error creating private key file: %v\n", err)
		os.Exit(1)
	}
	defer fdPrivate.Close()

	_, err = fdPrivate.Write(prikey)
	if err != nil {
		fmt.Printf("Error writing to private key file: %v\n", err)
		os.Exit(1)
	}

	// Create and write the public key to <out>_public.pem
	publicFile := *out + "_public.pem"
	fdPublic, err := os.Create(publicFile)
	if err != nil {
		fmt.Printf("Error creating public key file: %v\n", err)
		os.Exit(1)
	}
	defer fdPublic.Close()

	_, err = fdPublic.Write(pubkey)
	if err != nil {
		fmt.Printf("Error writing to public key file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Keys successfully generated:\n- Private key: %s\n- Public key: %s\n", privateFile, publicFile)
}
