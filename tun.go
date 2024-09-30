package sdtl

import "os"

type Utun struct {
	fd   int
	file *os.File
	Name string
}
