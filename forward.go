package sdtl

import "io"

func Forward(dst io.Writer, src io.Reader, bufsz int) error {
	buff := make([]byte, bufsz)
	for {
		n, e := src.Read(buff)
		if e != nil {
			return e
		}
		n, e = dst.Write(buff[:n])
		if e != nil {
			return e
		}
	}
}
