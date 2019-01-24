package npm

import (
	"context"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	npmgo "github.com/chrismatteson/npm-go"
)

func pathConfigConnection(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/connection",
		Fields: map[string]*framework.FieldSchema{
			"connection_uri": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "NPMJS URI",
			},
			"username": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Username of a NPMJS user",
			},
			"password": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Password of the provided NPMJS user",
			},
			"verify_connection": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Default:     true,
				Description: `If set, connection_uri is verified by actually connecting to the NPMJS API`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConnectionUpdate,
		},

		HelpSynopsis:    pathConfigConnectionHelpSyn,
		HelpDescription: pathConfigConnectionHelpDesc,
	}
}

func (b *backend) pathConnectionUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	uri := data.Get("connection_uri").(string)
	if uri == "" {
		return logical.ErrorResponse("missing connection_uri"), nil
	}

	username := data.Get("username").(string)
	if username == "" {
		return logical.ErrorResponse("missing username"), nil
	}

	password := data.Get("password").(string)
	if password == "" {
		return logical.ErrorResponse("missing password"), nil
	}

	// Don't check the connection_url if verification is disabled
	verifyConnection := data.Get("verify_connection").(bool)
	if verifyConnection {
		// Create NPMJS client
		client, err := npmgo.NewClient(uri, username, password)
		if err != nil {
			return nil, errwrap.Wrapf("failed to create client: {{err}}", err)
		}

		// Verify that configured credentials is capable of listing
		if _, err = client.ListTokens(); err != nil {
			return nil, errwrap.Wrapf("failed to validate the connection: {{err}}", err)
		}
	}

	// Store it
	entry, err := logical.StorageEntryJSON("config/connection", connectionConfig{
		URI:      uri,
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Reset the client connection
	b.resetClient(ctx)

	return nil, nil
}

// connectionConfig contains the information required to make a connection to a NPMJS repository
type connectionConfig struct {
	// URI of the NPMJS server
	URI string `json:"connection_uri"`

	// Username which has 'administrator' tag attached to it
	Username string `json:"username"`

	// Password for the Username
	Password string `json:"password"`
}

const pathConfigConnectionHelpSyn = `
Configure the connection URI, username, and password to talk to NPMJS HTTP API.
`

const pathConfigConnectionHelpDesc = `
This path configures the connection properties used to connect to NPMJS HTTP API.
The "connection_uri" parameter is a string that is used to connect to the API. The "username"
and "password" parameters are strings that are used as credentials to the API. The "verify_connection"
parameter is a boolean that is used to verify whether the provided connection URI, username, and password
are valid.

The URI looks like:
"http://localhost:15672"
`
