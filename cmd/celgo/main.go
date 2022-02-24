package main

import (
	"fmt"

	"github.com/zan8in/afrog/pkg/celgo"
)

func main() {
	var urltype celgo.UrlType

	urltype.Domain = "localhost"
	urltype.Path = "admin.php"
	urltype.Scheme = "https"

	fmt.Println(urltype)
}
