package sdtl

/*
#include "tun.h"
*/
import "C"
import (
	"fmt"
	"os"
)

type Utun struct {
	fd   int
	file *os.File
	Name string
}

func (u *Utun) SetIP(ip string, mask string) error {
	name := C.CString(u.Name)
	//defer func() { C.free(unsafe.Pointer(name)) }()

	fmt.Println(u.Name)

	csip := C.CString(ip)
	//defer func() { C.free(unsafe.Pointer(csip)) }()
	csmask := C.CString(mask)
	//defer func() { C.free(unsafe.Pointer(csip)) }()
	ret := C.configure_interface(name, csip, csmask)
	if ret == -1 {
		return fmt.Errorf("setting interface: %v", C.GoString(C.sys_error()))
	}
	return nil
}
