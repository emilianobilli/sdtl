package sdtl

/*
#include <stdio.h>
#include <stdlib.h>
#include "tun.h"
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"
)

type Utun struct {
	fd   int
	file *os.File
	Name string
	MTU  int
}

func (u *Utun) SetIP(ip string, mask string) error {
	name := C.CString(u.Name)
	defer func() { C.free(unsafe.Pointer(name)) }()

	csip := C.CString(ip)
	defer func() { C.free(unsafe.Pointer(csip)) }()
	csmask := C.CString(mask)
	defer func() { C.free(unsafe.Pointer(csmask)) }()
	ret := C.configure_interface(name, csip, csmask)
	if ret == -1 {
		return fmt.Errorf("setting interface address: %v", C.GoString(C.sys_error()))
	}
	return nil
}

func (u *Utun) SetMTU(val int) error {
	name := C.CString(u.Name)
	defer func() { C.free(unsafe.Pointer(name)) }()

	ret := C.set_mtu(name, C.int(val))
	if ret == -1 {
		return fmt.Errorf("setting interface mtu: %v", C.GoString(C.sys_error()))
	}
	u.MTU = val
	return nil
}

func (u *Utun) Close() {
	u.file.Close()
}

func (u *Utun) Read(buf []byte) (int, error) {
	if len(buf) < u.MTU {
		return 0, fmt.Errorf("invalid buf len, less than MTU")
	}
	return u.file.Read(buf[:u.MTU])
}

func (u *Utun) Write(buf []byte) (int, error) {
	if len(buf) > u.MTU {
		return 0, fmt.Errorf("invalid buf len, greather than MTU")
	}
	return u.file.Write(buf)
}
