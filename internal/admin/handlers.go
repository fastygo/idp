package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"idp-cyberos/internal/config"
	"idp-cyberos/internal/web/views"
)

type Handlers struct {
	cfg *config.Config
}

func NewHandlers(cfg *config.Config) *Handlers {
	return &Handlers{cfg: cfg}
}

type HankoUser struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type hankoListResponse []HankoUser

type hankoCreateRequest struct {
	Emails []hankoEmail `json:"emails"`
}

type hankoEmail struct {
	Address    string `json:"address"`
	IsPrimary  bool   `json:"is_primary"`
	IsVerified bool   `json:"is_verified"`
}

func (h *Handlers) HandleConsole(w http.ResponseWriter, r *http.Request) {
	hankoUsers, err := h.listUsers()
	if err != nil {
		log.Printf("admin: list users error: %v", err)
	}

	users := make([]views.UserEntry, len(hankoUsers))
	for i, u := range hankoUsers {
		users[i] = views.UserEntry{
			ID:        u.ID,
			Email:     u.Email,
			CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt,
		}
	}

	views.RenderAdminConsole(w, r, h.cfg, users)
}

func (h *Handlers) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	if err := h.createUser(email); err != nil {
		log.Printf("admin: create user error: %v", err)
		http.Error(w, fmt.Sprintf("Failed to create user: %v", err), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/console", http.StatusSeeOther)
}

func (h *Handlers) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.listUsers()
	if err != nil {
		log.Printf("admin: list users error: %v", err)
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func (h *Handlers) listUsers() ([]HankoUser, error) {
	adminURL := strings.TrimRight(h.cfg.HankoAdminURL, "/")
	if adminURL == "" {
		return nil, fmt.Errorf("hanko_admin_url not configured")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(adminURL + "/users")
	if err != nil {
		return nil, fmt.Errorf("fetch users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("admin API returned %d: %s", resp.StatusCode, string(body))
	}

	var users hankoListResponse
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("decode users: %w", err)
	}

	return users, nil
}

func (h *Handlers) createUser(email string) error {
	adminURL := strings.TrimRight(h.cfg.HankoAdminURL, "/")
	if adminURL == "" {
		return fmt.Errorf("hanko_admin_url not configured")
	}

	reqBody := hankoCreateRequest{
		Emails: []hankoEmail{
			{
				Address:    email,
				IsPrimary:  true,
				IsVerified: true,
			},
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(adminURL+"/users", "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin API returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
