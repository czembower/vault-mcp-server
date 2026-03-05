// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ReadEntityAlias creates a tool for reading Vault identity entity aliases.
func ReadEntityAlias(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_entity_alias",
			mcp.WithDescription("Read a Vault identity entity alias by id, including alias metadata and mount accessor."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("alias_id",
				mcp.Required(),
				mcp.Description("Entity alias ID to read.")),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Namespace path (for example 'admin/'). Defaults to current namespace.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readEntityAliasHandler(ctx, req, logger)
		},
	}
}

func readEntityAliasHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	aliasID, _ := args["alias_id"].(string)
	namespace, _ := args["namespace"].(string)
	if aliasID == "" {
		return mcp.NewToolResultError("alias_id is required"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	nsClient := vault
	if namespace != "" {
		nsClient = vault.WithNamespace(namespace)
	}

	readPath := fmt.Sprintf("identity/entity-alias/id/%s", aliasID)
	secret, err := nsClient.Logical().Read(readPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read entity alias: %v", err)), nil
	}
	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError("entity alias not found"), nil
	}

	result := map[string]interface{}{
		"alias_id":  aliasID,
		"namespace": namespace,
		"data":      secret.Data,
	}

	jsonResult, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonResult)), nil
}
