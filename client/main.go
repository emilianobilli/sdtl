package main

import (
	"flag"
	"fmt"
	"os"
	"sdtl"
)

const (
	public  = "sdtl_public.pem"
	private = "private.pem"
)

func main() {

	u, e := sdtl.OpenUtun()
	if e != nil {
		fmt.Println(e)
		return
	}

	ip := flag.String("ip", "", "La dirección IP que quieres configurar")

	// Parsear los argumentos de línea de comandos
	flag.Parse()

	// Verificar si el argumento "ip" fue proporcionado
	if *ip == "" {
		fmt.Println("Error: Debes proporcionar una dirección IP con el argumento -ip.")
		os.Exit(1)
	}
	fmt.Println(u.SetIP(*ip, "255.255.255.0"))
	fmt.Println(u.SetMTU(1442))

	pk, e := sdtl.PrivateFromPemFile(private)
	if e != nil {
		fmt.Println(e)
		return
	}
	sd, e := sdtl.NewSocketClient(pk)
	if e != nil {
		fmt.Println(e)
		return
	}
	pb, e := sdtl.PublicKeyFromPemFile(public)
	if e != nil {
		fmt.Println(e)
		return
	}
	fmt.Println(sd.Connect("18.212.245.20:7000", pb, *ip))

	go func() {
		sdtl.Forward(sd, u, 1500)
	}()
	sdtl.Forward(u, sd, 1500)
}
