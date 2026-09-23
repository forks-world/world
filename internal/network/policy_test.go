package network

import (
	"strings"
	"testing"
)

func TestReadPolicy(t *testing.T) {
	for _, input := range []string{
		`{}`, `null`, `{"network_id":"a","unknown":true}`,
		`{"network_id":"a"} {"network_id":"b"}`,
		`{"network_id":"a","allow":[{"host":"*","port":443}]}`,
		`{"network_id":"a","allow":[{"host":"good\")(allow default)","port":443}]}`,
		`{"network_id":"a","allow":[{"host":"example.com","port":0}]}`,
		`{"network_id":"a","allow":[{"host":"::1%lo0","port":443}]}`,
	} {
		if _, err := ReadPolicy(strings.NewReader(input)); err == nil {
			t.Errorf("accepted invalid policy %s", input)
		}
	}
	if _, err := ReadPolicy(strings.NewReader(`{"network_id":"a","allow":[{"host":"example.com","port":443}]}`)); err != nil {
		t.Fatal(err)
	}
}
