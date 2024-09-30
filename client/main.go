package main

import (
	"fmt"
	"sdtl"
)

const (
	public  = "sdtl_public.pem"
	private = "private.pem"
)

func main() {

	fmt.Println(sdtl.OpenUtun())

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
	fmt.Println(sd.Connect("18.212.245.20:7000", pb, "10.0.0.2"))

}
