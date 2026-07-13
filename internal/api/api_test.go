package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"m31labs.dev/mercutio/internal/cell"
	"m31labs.dev/mercutio/internal/transport"
)

func TestCreateAndEditAPI(t *testing.T) {
	store := cell.NewStore()
	hub := transport.NewCellHub(store)
	handler := New(store, hub)

	createRequest := httptest.NewRequest("POST", "/api/cells", strings.NewReader(`{"repoURL":"https://github.com/example/repo","branch":"main","profile":"standard"}`))
	createResponse := httptest.NewRecorder()
	handler.CreateCell(createResponse, createRequest)
	if createResponse.Code != 201 {
		t.Fatalf("create status = %d, body=%s", createResponse.Code, createResponse.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	editRequest := httptest.NewRequest("POST", "/api/cells/"+created.ID+"/edit", strings.NewReader(`{"path":"README.md","content":"updated"}`))
	editResponse := httptest.NewRecorder()
	handler.Edit(editResponse, editRequest)
	if editResponse.Code != 200 || !strings.Contains(editResponse.Body.String(), "updated") {
		t.Fatalf("edit response = %d, body=%s", editResponse.Code, editResponse.Body.String())
	}
}
