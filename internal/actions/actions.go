package actions

import (
	"net/url"
	"strings"

	"m31labs.dev/gosx/action"
	"m31labs.dev/mercutio/internal/cell"
	"m31labs.dev/mercutio/internal/model"
	"m31labs.dev/mercutio/internal/transport"
)

// New returns the GoSX server-action registry for browser mutations. JSON API
// routes remain available to non-browser clients, but the product UI does not
// need application-authored JavaScript to mutate control-plane state.
func New(store *cell.Store, hub *transport.CellHub) *action.Registry {
	registry := action.NewRegistry()
	registry.Register("create-cell", createCell(store, hub))
	registry.Register("edit-file", editFile(store, hub))
	registry.Register("undo-edit", undoEdit(store, hub, false))
	registry.Register("revert-agent-edit", undoEdit(store, hub, true))
	registry.Register("delete-file", deleteFile(store, hub))
	registry.Register("prompt", prompt(store, hub))
	registry.Register("destroy-cell", destroyCell(store, hub))
	registry.Register("approve-review", approveReview(store, hub))
	registry.Register("apply-policy", applyPolicy(store, hub))
	registry.Register("approve-secret-grant", approveSecretGrant(store, hub))
	registry.Register("acknowledge-review", acknowledgeReview(store, hub))
	registry.Register("reject-review", rejectReview(store, hub))
	registry.Register("adopt-shadow", shadowAction(store, hub, "adopt"))
	registry.Register("merge-shadow", shadowAction(store, hub, "merge"))
	registry.Register("discard-shadow", shadowAction(store, hub, "discard"))
	registry.Register("decide-action", decideAction(store, hub))
	return registry
}

func decideAction(store *cell.Store, hub *transport.CellHub) action.Handler {
	return func(ctx *action.Context) error {
		cellID := strings.TrimSpace(ctx.FormData["cellID"])
		requestID := strings.TrimSpace(ctx.FormData["requestID"])
		decision := strings.TrimSpace(ctx.FormData["decision"])
		if decision != "approve" && decision != "reject" {
			return action.Error(400, "action decision must be approve or reject")
		}
		snapshot, err := store.DecideActionApproval(cellID, requestID, "operator", decision == "approve")
		if err != nil {
			return action.Error(409, err.Error())
		}
		hub.BroadcastCell(snapshot)
		ctx.Redirect(viewPath(cellID, strings.TrimSpace(ctx.FormData["path"])))
		return nil
	}
}

func undoEdit(store *cell.Store, hub *transport.CellHub, agentOnly bool) action.Handler {
	return func(ctx *action.Context) error {
		cellID, path := identity(ctx)
		var snapshot model.CellSnapshot
		var err error
		if agentOnly {
			snapshot, err = store.RevertAgentEdit(cellID, path, "operator")
		} else {
			snapshot, err = store.UndoEdit(cellID, path, "operator")
		}
		if err != nil {
			return action.Error(409, err.Error())
		}
		hub.BroadcastCell(snapshot)
		ctx.Redirect(viewPath(cellID, path))
		return nil
	}
}

func shadowAction(store *cell.Store, hub *transport.CellHub, operation string) action.Handler {
	return func(ctx *action.Context) error {
		cellID, shadowID := strings.TrimSpace(ctx.FormData["cellID"]), strings.TrimSpace(ctx.FormData["shadowID"])
		var snapshot model.CellSnapshot
		var err error
		switch operation {
		case "adopt":
			snapshot, err = store.AdoptShadow(cellID, shadowID, "operator")
		case "merge":
			snapshot, _, err = store.MergeShadow(cellID, shadowID, "operator")
		case "discard":
			snapshot, err = store.DiscardShadow(cellID, shadowID, "operator", ctx.FormData["reason"])
		}
		if err != nil {
			return action.Error(400, err.Error())
		}
		hub.BroadcastCell(snapshot)
		ctx.Redirect(viewPath(cellID, strings.TrimSpace(ctx.FormData["path"])))
		return nil
	}
}

func acknowledgeReview(store *cell.Store, hub *transport.CellHub) action.Handler {
	return func(ctx *action.Context) error {
		cellID := strings.TrimSpace(ctx.FormData["cellID"])
		reviewID := strings.TrimSpace(ctx.FormData["reviewID"])
		snapshot, err := store.AcknowledgeReview(cellID, reviewID, "operator", ctx.FormData["reason"], ctx.FormData["ackSecret"] == "on", ctx.FormData["ackEvidence"] == "on")
		if err != nil {
			return action.Validation(err.Error(), map[string]string{"reason": err.Error()}, ctx.FormData)
		}
		hub.BroadcastCell(snapshot)
		ctx.Redirect(viewPath(cellID, strings.TrimSpace(ctx.FormData["path"])))
		return nil
	}
}

func rejectReview(store *cell.Store, hub *transport.CellHub) action.Handler {
	return func(ctx *action.Context) error {
		cellID := strings.TrimSpace(ctx.FormData["cellID"])
		reviewID := strings.TrimSpace(ctx.FormData["reviewID"])
		snapshot, prompt, err := store.RejectReview(cellID, reviewID, "operator", ctx.FormData["reason"])
		if err != nil {
			return action.Validation(err.Error(), map[string]string{"reason": err.Error()}, ctx.FormData)
		}
		hub.BroadcastCell(snapshot)
		if clientID := hub.AgentClient(cellID); clientID != "" {
			hub.SendAgent(clientID, "prompt:deliver", map[string]string{"cellID": cellID, "prompt": prompt})
		}
		ctx.Redirect(viewPath(cellID, strings.TrimSpace(ctx.FormData["path"])))
		return nil
	}
}

func approveSecretGrant(store *cell.Store, hub *transport.CellHub) action.Handler {
	return func(ctx *action.Context) error {
		cellID, requestID := strings.TrimSpace(ctx.FormData["cellID"]), strings.TrimSpace(ctx.FormData["requestID"])
		capability, err := store.MintSecretCapability(cellID, "operator", "secret:grant")
		if err != nil {
			return action.Error(400, err.Error())
		}
		snapshot, grant, err := store.ApproveSecretGrant(cellID, requestID, "operator", capability)
		if err != nil {
			return action.Error(403, err.Error())
		}
		request, ok := approvedSecretRequest(snapshot.SecretRequests, requestID)
		if !ok {
			return action.Error(500, "approved secret request disappeared")
		}
		if err = hub.DeliverTier2Grant(cellID, request, grant); err != nil {
			return action.Error(409, err.Error())
		}
		hub.BroadcastCell(snapshot)
		ctx.Redirect(viewPath(cellID, strings.TrimSpace(ctx.FormData["path"])))
		return nil
	}
}

func approvedSecretRequest(requests []model.SecretGrantRequest, id string) (model.SecretGrantRequest, bool) {
	for _, request := range requests {
		if request.ID == id {
			return request, true
		}
	}
	return model.SecretGrantRequest{}, false
}

func applyPolicy(store *cell.Store, hub *transport.CellHub) action.Handler {
	return func(ctx *action.Context) error {
		cellID, path := identity(ctx)
		snapshot, _, err := store.ApplyPolicy(ctx.Request.Context(), cellID, ctx.FormData["content"], "operator")
		if err != nil {
			return action.Validation(err.Error(), map[string]string{"content": err.Error()}, ctx.FormData)
		}
		hub.BroadcastCell(snapshot)
		ctx.Redirect(viewPath(cellID, path))
		return nil
	}
}

func createCell(store *cell.Store, hub *transport.CellHub) action.Handler {
	return func(ctx *action.Context) error {
		repoURL := strings.TrimSpace(ctx.FormData["repoURL"])
		if repoURL == "" {
			return action.Validation("repository is required", map[string]string{"repoURL": "required"}, ctx.FormData)
		}
		snapshot, err := store.Create(repoURL, ctx.FormData["branch"], ctx.FormData["profile"])
		if err != nil {
			return action.Validation(err.Error(), map[string]string{"repoURL": err.Error()}, ctx.FormData)
		}
		hub.RegisterCell(snapshot.ID)
		hub.BroadcastCell(snapshot)
		ctx.Redirect(viewPath(snapshot.ID, firstFile(snapshot)))
		return nil
	}
}

func editFile(store *cell.Store, hub *transport.CellHub) action.Handler {
	return func(ctx *action.Context) error {
		cellID, path := identity(ctx)
		if cellID == "" || path == "" {
			return action.Validation("cell and path are required", map[string]string{"path": "required"}, ctx.FormData)
		}
		snapshot, err := store.ApplyEdit(cellID, path, ctx.FormData["content"], "operator")
		if err != nil {
			return action.Validation(err.Error(), map[string]string{"content": err.Error()}, ctx.FormData)
		}
		hub.BroadcastCell(snapshot)
		ctx.Redirect(viewPath(cellID, path))
		return nil
	}
}

func deleteFile(store *cell.Store, hub *transport.CellHub) action.Handler {
	return func(ctx *action.Context) error {
		cellID, path := identity(ctx)
		snapshot, err := store.DeleteFile(cellID, path, "operator")
		if err != nil {
			return action.Error(400, err.Error())
		}
		hub.BroadcastCell(snapshot)
		ctx.Redirect(viewPath(cellID, firstFile(snapshot)))
		return nil
	}
}

func prompt(store *cell.Store, hub *transport.CellHub) action.Handler {
	return func(ctx *action.Context) error {
		cellID := strings.TrimSpace(ctx.FormData["cellID"])
		message := strings.TrimSpace(ctx.FormData["prompt"])
		if cellID == "" || message == "" {
			return action.Validation("prompt is required", map[string]string{"prompt": "required"}, ctx.FormData)
		}
		snapshot, err := store.Prompt(cellID, message)
		if err != nil {
			return action.Error(400, err.Error())
		}
		hub.BroadcastCell(snapshot)
		if clientID := hub.AgentClient(cellID); clientID != "" {
			hub.SendAgent(clientID, "prompt:deliver", map[string]string{"cellID": cellID, "prompt": message})
		}
		ctx.Redirect(viewPath(cellID, strings.TrimSpace(ctx.FormData["path"])))
		return nil
	}
}

func destroyCell(store *cell.Store, hub *transport.CellHub) action.Handler {
	return func(ctx *action.Context) error {
		cellID := strings.TrimSpace(ctx.FormData["cellID"])
		snapshot, err := store.Destroy(cellID)
		if err != nil {
			return action.Error(404, err.Error())
		}
		hub.DisconnectCell(cellID, "cell destroyed")
		hub.BroadcastCell(snapshot)
		ctx.Redirect("/")
		return nil
	}
}

func approveReview(store *cell.Store, hub *transport.CellHub) action.Handler {
	return func(ctx *action.Context) error {
		cellID := strings.TrimSpace(ctx.FormData["cellID"])
		reviewID := strings.TrimSpace(ctx.FormData["reviewID"])
		snapshot, err := store.ApproveReview(cellID, reviewID)
		if err != nil {
			return action.Error(404, err.Error())
		}
		hub.BroadcastCell(snapshot)
		ctx.Redirect(viewPath(cellID, strings.TrimSpace(ctx.FormData["path"])))
		return nil
	}
}

func identity(ctx *action.Context) (string, string) {
	return strings.TrimSpace(ctx.FormData["cellID"]), strings.TrimSpace(ctx.FormData["path"])
}

func firstFile(snapshot model.CellSnapshot) string {
	if len(snapshot.Files) > 0 {
		return snapshot.Files[0].Path
	}
	return ""
}

func viewPath(cellID, path string) string {
	values := url.Values{}
	values.Set("cell", cellID)
	if path != "" {
		values.Set("file", path)
	}
	return "/?" + values.Encode()
}
