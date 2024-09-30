package main

import (
	"fmt"
	"sdtl"
	"time"
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
	fmt.Println(u.SetIP("10.0.0.1", "255.255.255.0"))

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
	time.Sleep(time.Second * 50)
}
