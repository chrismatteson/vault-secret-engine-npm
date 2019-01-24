package npm

import (
	"context"
//	"fmt"

	"github.com/fatih/structs"
//	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},
		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},
			"password": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Password for account which token will be created for.",
			},
			"readonly": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Description: "If token is set as readonly.",
			},
                        "cidr_whitelist": &framework.FieldSchema{
                                Type:        framework.TypeString,
                                Description: "Array of cidrs for whitelisting.",
                        },
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathRoleRead,
			logical.UpdateOperation: b.pathRoleUpdate,
			logical.DeleteOperation: b.pathRoleDelete,
		},
		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

// Reads the role configuration from the storage
func (b *backend) Role(ctx context.Context, s logical.Storage, n string) (*roleEntry, error) {
	entry, err := s.Get(ctx, "role/"+n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Deletes an existing role
func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	return nil, req.Storage.Delete(ctx, "role/"+name)
}

// Reads an existing role
func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	role, err := b.Role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: structs.New(role).Map(),
	}, nil
}

// Lists all the roles registered with the backend
func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

// Registers a new role with the backend
func (b *backend) pathRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	password := d.Get("password").(string)
	readonly := d.Get("readonly").(bool)

	if password == "" {
		return logical.ErrorResponse("both password not specified"), nil
	}

	// Store it
	entry, err := logical.StorageEntryJSON("role/"+name, &roleEntry{
		Password: password,
		Readonly: readonly,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

// Role that defines the capabilities of the credentials issued against it
type roleEntry struct {
	Password string                     `json:"password" structs:"password" mapstructure:"password"`
	Readonly bool 			    `json:"readonly" structs:"readonly" mapstructure:"readonly"`
}

const pathRoleHelpSyn = `
Manage the roles that can be created with this backend.
`

const pathRoleHelpDesc = `
This path lets you manage the roles that can be created with this backend.

The "Password" parameter is required to create a new token. The "readonly"
parameter specifies if the token is readonly. The "cidr_whitelist"
parameter is an array of cidrs to whitelist for this token.
`
