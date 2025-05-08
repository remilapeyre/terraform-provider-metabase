package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/flovouin/terraform-provider-metabase/metabase"
)

// Ensures provider defined types fully satisfy framework interfaces.
var _ provider.Provider = &MetabaseProvider{}

// Handles Metabase-related resources.
type MetabaseProvider struct {
	// Version is set to the provider version on release, "dev" when the provider is built and ran locally, and "test"
	// when running acceptance testing.
	version string
}

// The Terraform model for the provider.
type MetabaseProviderModel struct {
	Endpoint types.String      `tfsdk:"endpoint"` // The URL to the Metabase API.
	Username types.String      `tfsdk:"username"` // The user name (or email address) to use to authenticate.
	Password types.String      `tfsdk:"password"` // The password to use to authenticate.
	ApiKey   types.String      `tfsdk:"api_key"`  // The API key to use to authenticate. This can be used instead of a user name and password.
	TLS      *MetabaseTLSModel `tfsdk:"tls"`      // The TLS configuration to use to connect to the Metabase API.
}

type MetabaseTLSModel struct {
	CaCertFile     types.String `tfsdk:"ca_cert_file"`     // The path to a CA certificate file to use to verify the Metabase server's certificate.  // The path to a directory containing CA certificate files to use to verify the Metabase server's certificate.
	TlsServerName  types.String `tfsdk:"tls_server_name"`  // The name of the server to verify the certificate against.
	SkipTlsVerify  types.Bool   `tfsdk:"skip_tls_verify"`  // Whether to skip the verification of the Metabase server's certificate.
	ClientCertFile types.String `tfsdk:"client_cert_file"` // The path to a client certificate file to use to authenticate to the Metabase server.
	ClientKeyFile  types.String `tfsdk:"client_key_file"`  // The path to a client key file to use to authenticate to the Metabase server.
}

func (p *MetabaseProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "metabase"
	resp.Version = p.version
}

func (p *MetabaseProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `The Metabase provider allows managing both metadata (collections, permissions groups) and actual visualizations (cards/questions and dashboards).

While most Terraform resources fully define the Metabase objects using attributes, the most complex ones (cards and dashboards) must be defined using JSON (and possibly templates).`,

		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "The URL to the Metabase API.",
				Required:            true,
			},
			"username": schema.StringAttribute{
				MarkdownDescription: "The user name (or email address) to use to authenticate.",
				Optional:            true,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "The password to use to authenticate.",
				Optional:            true,
				Sensitive:           true,
			},
			"api_key": schema.StringAttribute{
				MarkdownDescription: "The API key to use to authenticate. This can be used instead of a user name and password.",
				Optional:            true,
				Sensitive:           true,
			},
		},
		Blocks: map[string]schema.Block{
			"tls": schema.SingleNestedBlock{
				MarkdownDescription: "The TLS configuration to use to connect to the Metabase API.",
				Attributes: map[string]schema.Attribute{
					"ca_cert_file": schema.StringAttribute{
						MarkdownDescription: "The path to a CA certificate file to use to verify the Metabase server's certificate.",
						Optional:            true,
					},
					"tls_server_name": schema.StringAttribute{
						MarkdownDescription: "The name of the server to verify the certificate against.",
						Optional:            true,
					},
					"skip_tls_verify": schema.BoolAttribute{
						MarkdownDescription: "Whether to skip the verification of the Metabase server's certificate.",
						Optional:            true,
					},
					"client_cert_file": schema.StringAttribute{
						MarkdownDescription: "The path to a client certificate file to use to authenticate to the Metabase server.",
						Optional:            true,
					},
					"client_key_file": schema.StringAttribute{
						MarkdownDescription: "The path to a client key file to use to authenticate to the Metabase server.",
						Optional:            true,
					},
				},
			},
		},
	}
}

func (p *MetabaseProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data MetabaseProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	var err error
	var authenticatedClient *metabase.ClientWithResponses

	client := cleanhttp.DefaultPooledClient()
	opts := []metabase.ClientOption{
		metabase.WithHTTPClient(client),
	}

	if data.TLS != nil {
		clientTLSConfig := &tls.Config{}
		config := data.TLS

		switch {
		case !config.ClientCertFile.IsNull() && !config.ClientKeyFile.IsNull():
			clientCert, err := tls.LoadX509KeyPair(config.ClientCertFile.ValueString(), config.ClientKeyFile.ValueString())
			if err != nil {
				resp.Diagnostics.AddError("Failed to load client certificate and key.", err.Error())
				return
			}
			clientTLSConfig.Certificates = []tls.Certificate{clientCert}

		case !config.ClientCertFile.IsNull() || !config.ClientKeyFile.IsNull():
			resp.Diagnostics.AddError("Either both client certificate and key must be provided or none of them.", "")
			return
		}

		if config.SkipTlsVerify.ValueBool() {
			clientTLSConfig.InsecureSkipVerify = true
		}

		if config.TlsServerName.ValueString() != "" {
			clientTLSConfig.ServerName = config.TlsServerName.ValueString()
		}

		if !config.CaCertFile.IsNull() {
			clientTLSConfig.RootCAs = x509.NewCertPool()
			caCert, err := os.ReadFile(config.CaCertFile.ValueString())
			if err != nil {
				resp.Diagnostics.AddError("Failed to read CA certificate file.", err.Error())
				return
			}
			clientTLSConfig.RootCAs.AppendCertsFromPEM(caCert)
		}

		client.Transport.(*http.Transport).TLSClientConfig = clientTLSConfig
	}

	if !data.Username.IsNull() && !data.Password.IsNull() {
		if !data.ApiKey.IsNull() {
			resp.Diagnostics.AddError("Only one of username / password or API key can be provided.", "")
			return
		}

		authenticatedClient, err = metabase.MakeAuthenticatedClientWithUsernameAndPassword(
			ctx,
			data.Endpoint.ValueString(),
			data.Username.ValueString(),
			data.Password.ValueString(),
			opts...,
		)
		if err != nil {
			resp.Diagnostics.AddError("Failed to create the Metabase client from username and password.", err.Error())
			return
		}
	} else if !data.ApiKey.IsNull() {
		if !data.Username.IsNull() || !data.Password.IsNull() {
			resp.Diagnostics.AddError("Only one of username / password or API key can be provided.", "")
			return
		}

		authenticatedClient, err = metabase.MakeAuthenticatedClientWithApiKey(
			ctx,
			data.Endpoint.ValueString(),
			data.ApiKey.ValueString(),
			opts...,
		)
		if err != nil {
			resp.Diagnostics.AddError("Failed to create the Metabase client from the API key.", err.Error())
			return
		}
	} else {
		resp.Diagnostics.AddError("Either username / password or API key must be provided.", "")
		return
	}

	resp.DataSourceData = authenticatedClient
	resp.ResourceData = authenticatedClient
}

func (p *MetabaseProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCardResource,
		NewCollectionGraphResource,
		NewCollectionResource,
		NewDashboardResource,
		NewDatabaseResource,
		NewPermissionsGraphResource,
		NewPermissionsGroupResource,
		NewTableResource,
	}
}

func (p *MetabaseProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewTableDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &MetabaseProvider{
			version: version,
		}
	}
}
