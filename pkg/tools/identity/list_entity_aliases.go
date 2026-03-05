// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ListEntityAliases creates a tool for listing Vault identity entity aliases.
func ListEntityAliases(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_entity_aliases",
			mcp.WithDescription("List Vault identity entity aliases by id."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Namespace path (for example 'admin/'). Defaults to current namespace.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listEntityAliasesHandler(ctx, req, logger)
		},
	}
}

func listEntityAliasesHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	namespace, _ := args["namespace"].(string)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	nsClient := vault
	if namespace != "" {
		nsClient = vault.WithNamespace(namespace)
	}

	listPath := "identity/entity-alias/id"
	secret, err := nsClient.Logical().List(listPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list entity aliases: %v", err)), nil
	}
	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultText(fmt.Sprintf("No entity aliases found at %s", listPath)), nil
	}

	keysRaw, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return mcp.NewToolResultText(fmt.Sprintf("No entity aliases found at %s", listPath)), nil
	}

	keys := make([]string, 0, len(keysRaw))
	for _, k := range keysRaw {
		if s, ok := k.(string); ok {
			keys = append(keys, s)
		}
	}
	sort.Strings(keys)

	result := map[string]interface{}{
		"namespace": namespace,
		"keys":      keys,
		"count":     len(keys),
	}

	jsonResult, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonResult)), nil
}
