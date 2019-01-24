package npm

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	npmgo "github.com/chrismatteson/npm-go"
)

func pathCreds(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredsRead,
		},

		HelpSynopsis:    pathRoleCreateReadHelpSyn,
		HelpDescription: pathRoleCreateReadHelpDesc,
	}
}

// Issues the credential based on the role name
func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	// Get the role
	role, err := b.Role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", name)), nil
	}


	// Get the client configuration
	client, err := b.Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return logical.ErrorResponse("failed to get the client"), nil
	}

	password := client.Password

	// Generate credentials in the backend, with the NPMJS server
	tokenhash, err := client.CreateToken(npmgo.TokenSettings{
		Password: password,
		Readonly: false,
	})
	if  err != nil {
		return nil, fmt.Errorf("failed to create a new token")
	}

	// Return the secret
	resp := b.Secret(SecretCredsType).Response(map[string]interface{}{
		"token": tokenhash.Token,
	}, map[string]interface {}{
		"id": tokenhash.Id,
	})

	// Determine if we have a lease
//	lease, err := b.Lease(ctx, req.Storage)
//	if err != nil {
//		return nil, err
//	}

//	if lease != nil {
//		resp.Token.TTL = lease.TTL
//		resp.Token.MaxTTL = lease.MaxTTL
//	}

	return resp, nil
}

const pathRoleCreateReadHelpSyn = `
Request NPMJS token for a certain role.
`

const pathRoleCreateReadHelpDesc = `
This path reads NPMJS credentials for a certain role. The
NPMJS token will be generated on demand and will be automatically
revoked when the lease is up.
`
