package npm

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// SecretCredsType is the key for this backend's secrets.
const SecretCredsType = "creds"

func secretCreds(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretCredsType,
		Fields: map[string]*framework.FieldSchema{
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "NPMJS token",
			},
			"id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Id of token",
			},
		},
		Renew:  b.secretCredsRenew,
		Revoke: b.secretCredsRevoke,
	}
}

// Renew the previously issued secret
func (b *backend) secretCredsRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the lease information
	lease, err := b.Lease(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		lease = &configLease{}
	}

	resp := &logical.Response{Secret: req.Secret}
//	resp.Secret.TTL = lease.TTL
//	resp.Secret.MaxTTL = lease.MaxTTL
	return resp, nil
}

// Revoke the previously issued secret
func (b *backend) secretCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the username from the internal data
	idRaw, ok := req.Secret.InternalData["id"]
	if !ok {
		return nil, fmt.Errorf("secret is missing id internal data")
	}
	id := idRaw.(string)

	// Get our connection
	client, err := b.Client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if _, err = client.DeleteToken(id); err != nil {
		return nil, errwrap.Wrapf("could not delete token: {{err}}", err)
	}

	return nil, nil
}
