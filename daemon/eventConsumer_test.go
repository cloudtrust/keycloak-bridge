package main

import (
	"testing"
	"net/http"
	"log"
	"fmt"
	//"time"
)

func TestEventConsumer_Main(t *testing.T) {
	//
	//var netClient = &http.Client{
	//	Timeout: time.Second * 10,
	//}

	resp, err := http.Get("http://localhost:8888/event/id")

	if err != nil {
		log.Fatal(err)
	}



	fmt.Println(resp.StatusCode)

}

