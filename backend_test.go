package npm

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"

//	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"
	npmgo "github.com/chrismatteson/npm-go"
	"github.com/mitchellh/mapstructure"
)

const (
	envNPMJSConnectionURI = "NPMJS_CONNECTION_URI"
	envNPMJSUsername      = "NPMJS_USERNAME"
	envNPMJSPassword      = "NPMJS_PASSWORD"
)

func TestBackend_basic(t *testing.T) {
	if os.Getenv(logicaltest.TestEnvVar) == "" {
		t.Skip(fmt.Sprintf("Acceptance tests skipped unless env '%s' set", logicaltest.TestEnvVar))
		return
	}
	b, _ := Factory(context.Background(), logical.TestBackendConfig())

	uri := os.Getenv(envNPMJSConnectionURI)

	logicaltest.Test(t, logicaltest.TestCase{
		PreCheck:       testAccPreCheckFunc(t, uri),
		LogicalBackend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfig(t, uri),
			testAccStepRole(t),
			testAccStepReadCreds(t, b, uri, "npm"),
		},
	})

}

func TestBackend_roleCrud(t *testing.T) {
	if os.Getenv(logicaltest.TestEnvVar) == "" {
		t.Skip(fmt.Sprintf("Acceptance tests skipped unless env '%s' set", logicaltest.TestEnvVar))
		return
	}
	b, _ := Factory(context.Background(), logical.TestBackendConfig())

	uri := os.Getenv(envNPMJSConnectionURI)
	password := os.Getenv(envNPMJSPassword)

	logicaltest.Test(t, logicaltest.TestCase{
		PreCheck:       testAccPreCheckFunc(t, uri),
		LogicalBackend: b,
		Steps: []logicaltest.TestStep{
			testAccStepConfig(t, uri),
			testAccStepRole(t),
			testAccStepReadRole(t, "npm", password, false),
			testAccStepDeleteRole(t, "npm"),
			testAccStepReadRole(t, "npm", "", false),
		},
	})
}

func testAccPreCheckFunc(t *testing.T, uri string) func() {
	return func() {
		if uri == "" {
			t.Fatal("NPMJS URI must be set for acceptance tests")
		}
	}
}

func testAccStepConfig(t *testing.T, uri string) logicaltest.TestStep {
	username := os.Getenv(envNPMJSUsername)
	if len(username) == 0 {
		username = "guest"
	}
	password := os.Getenv(envNPMJSPassword)
	if len(password) == 0 {
		password = "guest"
	}

	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "config/connection",
		Data: map[string]interface{}{
			"connection_uri": uri,
			"username":       username,
			"password":       password,
		},
	}
}

func testAccStepRole(t *testing.T) logicaltest.TestStep {
	password := os.Getenv(envNPMJSPassword)
	if len(password) == 0 {
		password = "guest"
	}

	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "roles/npm",
		Data: map[string]interface{}{
			"password": password,
			"readonly": false,
		},
	}
}

func testAccStepDeleteRole(t *testing.T, n string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.DeleteOperation,
		Path:      "roles/" + n,
	}
}

func testAccStepReadCreds(t *testing.T, b logical.Backend, uri, name string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "creds/" + name,
		Check: func(resp *logical.Response) error {
			var d struct {
				Token string `mapstructure:"token"`
				Id    string `mapstructure:"id"`
				Password string `mapstructure:"password"`
			}
			if err := mapstructure.Decode(resp.Data, &d); err != nil {
				return err
			}
			log.Printf("[WARN] Generated credentials: %v", d)

			client, err := npmgo.NewTokenClient(uri, d.Token)
			if err != nil {
				t.Fatal(err)
			}

			_, err = client.Whoami()
			if err != nil {
				t.Fatalf("unable to run whomai with generated credentials: %s", err)
			}

			resp, err = b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.RevokeOperation,
				Secret: &logical.Secret{
					InternalData: map[string]interface{}{
						"secret_type": "creds",
						"id":          d.Id,
					},
				},
			})
			if err != nil {
				return err
			}
			if resp != nil {
				if resp.IsError() {
					return fmt.Errorf("error on resp: %#v", *resp)
				}
			}

			return nil
		},
	}
}

func testAccStepReadRole(t *testing.T, name string, password string, readonly bool) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "roles/" + name,
		Check: func(resp *logical.Response) error {
			if resp == nil {
				if password == "" && readonly == false {
					return nil
				}

				return fmt.Errorf("bad: %#v", resp)
			}

			var d struct {
				Password  string   `mapstructure:"password"`
				Readonly  bool     `mapstructure:"readonly"`
			}
			if err := mapstructure.Decode(resp.Data, &d); err != nil {
				return err
			}

			if d.Password != password {
				return fmt.Errorf("bad: %#v", resp)
			}

			if d.Readonly != readonly {
				return fmt.Errorf("bad: %#v", resp)
			}

			return nil
		},
	}
}
