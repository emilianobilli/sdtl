package main

import (
	"fmt"
	"sdtl"
)

func main() {
	s, e := sdtl.SDTLServer("config.json")
	if e != nil {
		fmt.Println(e)
		return
	}
	s.ListenAndServe()
}
