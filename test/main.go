package main

import (
	"flag"
	"fmt"
	"sdtl"
	"ulan"
)

const (
	public  = "public.pem"
	private = "private.pem"
)

func main() {
	var sock *sdtl.Socket
	var err error
	// Definir el argumento de la línea de comandos para el servidor
	server := flag.String("server", "", "Address of the server to connect to")
	listen := flag.Bool("listen", false, "Is server")
	flag.Parse() // Parsear los argumentos de la línea de comandos

	fmt.Println("Server: ", *server)
	fmt.Println("Listen: ", *listen)

	// Verificar que se haya pasado un servidor
	if !*listen && *server == "" {
		fmt.Println("Error: server address is required")
		return
	}

	eth, err := ulan.UlanDriver()
	if err != nil {
		fmt.Println("open driver: %v", err)
		return
	}

	pubkey, err := sdtl.PublicKeyFromPemFile(public)
	if err != nil {
		fmt.Println("public key: %v", err)
		return
	}

	prikey, err := sdtl.PrivateFromPemFile(private)
	if err != nil {
		fmt.Println("private key: %v", err)
		return
	}

	if *listen {
		sock, err = sdtl.NewSocket(*server, prikey)
		if err != nil {
			fmt.Println("open create socket: %v", err)
			return
		}
	} else {
		sock, err = sdtl.NewSocket("", prikey)
		if err != nil {
			fmt.Println("open create socket: %v", err)
			return
		}
	}

	if *listen {
		e := sock.Accept("", pubkey)
		if e != nil {
			fmt.Println("connect to server: %v", e)
			return
		}
	} else if e := sock.Connect(*server, pubkey); e != nil {
		fmt.Println("connect to server: %v", e)
		return
	}

	go func() {
		for {
			frame, e := eth.ReadEthFrame()
			fmt.Println(frame.GetIP())
			if e != nil {
				fmt.Println("read frame: %v", e)
				return
			}
			if e := sock.Send(frame.RawIP()); e != nil {
				fmt.Println("sdtl send frame: %v", e)
				return
			}
		}
	}()

	for {
		b, e := sock.Recv()
		if e != nil {
			fmt.Println("sdtl recv frame: %v", e)
			return
		}
		eth.WriteRawIP(b)
	}

}
