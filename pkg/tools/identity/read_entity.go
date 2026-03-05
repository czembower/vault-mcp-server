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

// ReadEntity creates a tool for reading Vault identity entities.
func ReadEntity(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_entity",
			mcp.WithDescription("Read a Vault identity entity by id or by name, including entity metadata and aliases."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("entity_id",
				mcp.DefaultString(""),
				mcp.Description("Entity ID to read. Use either entity_id or entity_name.")),
			mcp.WithString("entity_name",
				mcp.DefaultString(""),
				mcp.Description("Entity name to read. Use either entity_id or entity_name.")),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Namespace path (for example 'admin/'). Defaults to current namespace.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readEntityHandler(ctx, req, logger)
		},
	}
}

func readEntityHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	entityID, _ := args["entity_id"].(string)
	entityName, _ := args["entity_name"].(string)
	namespace, _ := args["namespace"].(string)

	if entityID == "" && entityName == "" {
		return mcp.NewToolResultError("one of entity_id or entity_name is required"), nil
	}
	if entityID != "" && entityName != "" {
		return mcp.NewToolResultError("provide only one of entity_id or entity_name"), nil
	}

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	nsClient := vault
	if namespace != "" {
		nsClient = vault.WithNamespace(namespace)
	}

	readPath := ""
	lookup := map[string]string{}
	if entityID != "" {
		readPath = fmt.Sprintf("identity/entity/id/%s", entityID)
		lookup["entity_id"] = entityID
	} else {
		readPath = fmt.Sprintf("identity/entity/name/%s", entityName)
		lookup["entity_name"] = entityName
	}

	secret, err := nsClient.Logical().Read(readPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read entity: %v", err)), nil
	}
	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError("entity not found"), nil
	}

	result := map[string]interface{}{
		"lookup":    lookup,
		"namespace": namespace,
		"data":      secret.Data,
	}

	jsonResult, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonResult)), nil
}
