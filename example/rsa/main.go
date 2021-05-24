package main

import (
	"fmt"
	"github.com/wangjuelong/goEncrypt"
)

func main() {
	pri, pub, err := goEncrypt.GetRsaKey()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("private key:")
	fmt.Println(pri.String())

	fmt.Println("public key:")
	fmt.Print(pub.String())
}
