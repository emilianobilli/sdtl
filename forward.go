package sdtl

import (
	"fmt"
	"io"
)

func Forward(dst io.Writer, src io.Reader, bufsz int) error {
	buff := make([]byte, bufsz)
	for {
		n, e := src.Read(buff)
		fmt.Println("Read", e)
		if e != nil {
			return e
		}
		fmt.Println("Leido", n)
		n, e = dst.Write(buff[:n])
		fmt.Println("Write", e)
		if e != nil {
			return e
		}
	}
}
