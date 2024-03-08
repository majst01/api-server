package project

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/metal-stack/metal-lib/pkg/testcommon"
)

func Test_validateInviteSecret(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		wantErr error
	}{
		{
			name:    "valid secret key returned from generate func",
			s:       generateInviteSecret(),
			wantErr: nil,
		},
		{
			name:    "unexpected length",
			s:       "foo",
			wantErr: fmt.Errorf("unexpected invite secret length"),
		},
		{
			name:    "unexpected chars",
			s:       strings.Repeat("*", inviteSecretLength),
			wantErr: fmt.Errorf("invite secret contains unexpected characters: '*'"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInviteSecret(tt.s)
			if diff := cmp.Diff(tt.wantErr, err, testcommon.ErrorStringComparer()); diff != "" {
				t.Errorf("error diff (+got -want):\n %s", diff)
			}
		})
	}
}
