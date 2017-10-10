package transport
//
//import (
//	"net/http"
//	"context"
//	"fmt"
//	"github.com/go-kit/kit/endpoint"
//	"encoding/json"
//	httptransport "github.com/go-kit/kit/transport/http"
//)
//
//func MakeReceiver() func(http.ResponseWriter, *http.Request) {
//	return func(w http.ResponseWriter, r *http.Request) {
//		w.Write([]byte(fmt.Sprintf("Reception OK\n")))
//	}
//}
//
//func MakeReceiverHandler(e endpoint.Endpoint) *httptransport.Server{
//	return httptransport.NewServer(e, decodeKeycloakEventsReceiverRequest, encodeResponse )
//}
//
////func decodeKeycloakEventsReceiverRequest(_ context.Context, r *http.Request) (interface{}, error) {
////	var request KeycloakEventReceiverRequest
////	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
////		return nil, err
////	}
////	return request, nil
////}
//
//func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
//	return json.NewEncoder(w).Encode(response)
//}
//
//
//
//func MakeReceiverHandler2(e endpoint.Endpoint) func(http.ResponseWriter, *http.Request){
//	return func(w http.ResponseWriter, r *http.Request) {
//
//		w.Write([]byte(fmt.Sprintf("Reception OK\n")))
//	}
//}
