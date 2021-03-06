package uhost

import (
	"github.com/ucloud/ucloud-sdk-go/ucloud"
	"github.com/ucloud/ucloud-sdk-go/ucloud/auth"
)

// UHostClient is the client of UHost
type UHostClient struct {
	*ucloud.Client
}

// NewClient will return a instance of UHostClient
func NewClient(config *ucloud.Config, credential *auth.Credential) *UHostClient {
	meta := ucloud.ClientMeta{Product: "UHost"}
	client := ucloud.NewClientWithMeta(config, credential, meta)
	return &UHostClient{
		client,
	}
}
