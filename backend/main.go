package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

type WhitelistRequest struct {
	Duration string `json:"duration"`
}

type WhitelistResponse struct {
	Message string `json:"message"`
	IP      string `json:"ip"`
}

type StatusResponse struct {
	IP            string `json:"ip"`
	Whitelisted   bool   `json:"whitelisted"`
	ExpiresAt     string `json:"expiresAt,omitempty"`
	TimeRemaining string `json:"timeRemaining,omitempty"`
}

var (
	apiToken = os.Getenv("CLOUDFLARE_API_TOKEN")
	zoneID   = os.Getenv("CLOUDFLARE_ZONE_ID")
	// For this example, we'll assume we are adding to an existing IP List utilized by a WAF rule
	// OR adding a literal IP rule to a Firewall Access Rule.
	// Let's go with Firewall Access Rule (IP Access Rules) as it's simpler for "whitelist IP".
	// Alternatively, replacing an IP List content is common for Zero Trust.
	// Given "Cloudflare Access policy", we'd modify an Access Group.
	// We'll implement updating an Access Policy (Account Level).
	accountID = os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	policyID  = os.Getenv("CLOUDFLARE_POLICY_ID")

	// Persistence
	storeFile = "whitelist_store.json"
	store     = &WhitelistStore{
		Entries: make(map[string]time.Time),
	}
)

// WhitelistStore handles persistence
type WhitelistStore struct {
	sync.RWMutex
	Entries map[string]time.Time `json:"entries"`
}

func (s *WhitelistStore) Load() error {
	s.Lock()
	defer s.Unlock()

	f, err := os.Open(storeFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	bytes, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	return json.Unmarshal(bytes, &s.Entries)
}

func (s *WhitelistStore) Save() error {
	s.RLock()
	defer s.RUnlock()

	bytes, err := json.MarshalIndent(s.Entries, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(storeFile, bytes, 0644)
}

func (s *WhitelistStore) Add(ip string, expiry time.Time) {
	s.Lock()
	s.Entries[ip] = expiry
	s.Unlock()
	s.Save()
}

func (s *WhitelistStore) Remove(ip string) {
	s.Lock()
	delete(s.Entries, ip)
	s.Unlock()
	s.Save()
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Log configuration status
	log.Println("=== Cloudflare IP Whitelist Service ===")
	log.Printf("Port: %s", port)
	log.Printf("Cloudflare API Token: %s", maskString(apiToken))
	log.Printf("Cloudflare Account ID: %s", maskString(accountID))
	log.Printf("Cloudflare Policy ID: %s", maskString(policyID))

	if apiToken == "" || accountID == "" || policyID == "" {
		log.Println("WARNING: Cloudflare credentials not fully configured!")
		log.Println("WARNING: IPs will only be stored locally, not added to Cloudflare policy")
	} else {
		log.Println("Cloudflare integration: ENABLED")
	}

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // Adjust for production
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Static files from /dist
	workDir, _ := os.Getwd()
	filesDir := http.Dir(fmt.Sprintf("%s/dist", workDir))
	FileServer(r, "/", filesDir)

	r.Get("/ip", handleGetIP)
	r.Get("/status", handleStatus)
	r.Post("/whitelist", handleWhitelist)
	r.Delete("/whitelist", handleDeleteWhitelist)

	// Load state
	if err := store.Load(); err != nil {
		log.Printf("Error loading store: %v", err)
	} else {
		log.Printf("Loaded %d whitelisted IPs from store", len(store.Entries))
	}

	// Start Daemon
	go startExpiryDaemon()

	fmt.Printf("Starting server on port %s...\n", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

func handleGetIP(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	resp := map[string]string{"ip": ip}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// formatTimeRemaining converts a duration to a human-readable format
// e.g., "2 hours 15 minutes" or "45 minutes" or "30 seconds"
func formatTimeRemaining(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	var parts []string
	if hours > 0 {
		if hours == 1 {
			parts = append(parts, "1 hour")
		} else {
			parts = append(parts, fmt.Sprintf("%d hours", hours))
		}
	}
	if minutes > 0 {
		if minutes == 1 {
			parts = append(parts, "1 minute")
		} else {
			parts = append(parts, fmt.Sprintf("%d minutes", minutes))
		}
	}
	if seconds > 0 && hours == 0 { // Only show seconds if less than an hour
		if seconds == 1 {
			parts = append(parts, "1 second")
		} else {
			parts = append(parts, fmt.Sprintf("%d seconds", seconds))
		}
	}

	if len(parts) == 0 {
		return "less than a second"
	}

	return strings.Join(parts, " ")
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	if ip == "" {
		http.Error(w, "Could not determine client IP", http.StatusBadRequest)
		return
	}

	// Validate IP
	if net.ParseIP(ip) == nil {
		http.Error(w, "Invalid IP address detected", http.StatusBadRequest)
		return
	}

	// Check local store
	store.RLock()
	expiry, existsInStore := store.Entries[ip]
	store.RUnlock()

	// Also check Cloudflare policy if credentials are configured
	existsInCloudflare := false
	if apiToken != "" && accountID != "" && policyID != "" {
		if err := checkIPInCloudflarePolicy(r.Context(), ip); err == nil {
			existsInCloudflare = true
		}
	}

	// IP is whitelisted if it exists in BOTH store AND Cloudflare (or if Cloudflare is not configured)
	whitelisted := existsInStore
	if apiToken != "" && accountID != "" && policyID != "" {
		whitelisted = existsInStore && existsInCloudflare
	}

	resp := StatusResponse{
		IP:          ip,
		Whitelisted: whitelisted,
	}

	if existsInStore {
		resp.ExpiresAt = expiry.Format(time.RFC3339)
		timeRemaining := time.Until(expiry)
		resp.TimeRemaining = formatTimeRemaining(timeRemaining)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleDeleteWhitelist(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	if ip == "" {
		http.Error(w, "Could not determine client IP", http.StatusBadRequest)
		return
	}

	// Validate IP
	if net.ParseIP(ip) == nil {
		http.Error(w, "Invalid IP address detected", http.StatusBadRequest)
		return
	}

	log.Printf("Removing IP from whitelist: %s", ip)

	// Always attempt to remove from Cloudflare (even if not in local store)
	// This ensures sync if local store and Cloudflare are out of sync
	if err := removeFromCloudflareAccessPolicy(r.Context(), ip); err != nil {
		log.Printf("Error removing from Cloudflare: %v", err)
		if apiToken != "" {
			http.Error(w, "Failed to remove from Cloudflare policy", http.StatusInternalServerError)
			return
		}
	}

	// Remove from store (if exists)
	store.Remove(ip)
	log.Printf("IP %s removed from whitelist and Cloudflare policy", ip)

	resp := map[string]string{
		"message": "IP removed from whitelist",
		"ip":      ip,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleWhitelist(w http.ResponseWriter, r *http.Request) {
	// 1. Extract IP
	ip := getClientIP(r)
	if ip == "" {
		http.Error(w, "Could not determine client IP", http.StatusBadRequest)
		return
	}

	// Validate IP
	if net.ParseIP(ip) == nil {
		http.Error(w, "Invalid IP address detected", http.StatusBadRequest)
		return
	}

	// 2. Parse Duration
	var req WhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	duration := 60 * time.Minute // default
	// Support "0.5" for 30s, or explicit units if frontend sent them.
	// We assume frontend sends string minutes usually.
	if d, err := time.ParseDuration(req.Duration + "m"); err == nil {
		duration = d
	} else if d, err := time.ParseDuration(req.Duration); err == nil {
		// Fallback for "30s" etc
		duration = d
	}

	// 3. Check if IP already exists (extension case)
	store.RLock()
	existingExpiry, exists := store.Entries[ip]
	store.RUnlock()

	if exists {
		log.Printf("Extending whitelist for IP: %s by %v (current expiry: %s)", ip, duration, existingExpiry)
		// Extend from now, not from existing expiry
		newExpiry := time.Now().Add(duration)
		store.Add(ip, newExpiry)
		log.Printf("IP %s expiry extended to %s", ip, newExpiry)
	} else {
		log.Printf("Whitelisting IP: %s for %v", ip, duration)

		// 4. Update Cloudflare (only for new IPs)
		if err := addToCloudflareAccessPolicy(r.Context(), ip); err != nil {
			log.Printf("Error updating Cloudflare: %v", err)
			http.Error(w, fmt.Sprintf("Failed to update Cloudflare policy: %v", err), http.StatusInternalServerError)
			return
		}

		// Persist Expiry only after successful Cloudflare update
		expiry := time.Now().Add(duration)
		store.Add(ip, expiry)
		log.Printf("IP %s added to store, expires at %s", ip, expiry)
	}

	resp := WhitelistResponse{
		Message: "Success",
		IP:      ip,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func getClientIP(r *http.Request) string {
	// Priority 1: CF-Connecting-IP (Cloudflare)
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}

	// Priority 2: X-Forwarded-For
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}

	// Priority 3: RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	// If the IP is private (Localhost or Docker Network), fallback to fetching public IP
	// This ensures local testing works by whitelisting the actual Public IP.
	if isPrivateIP(ip) {
		log.Printf("Detected private IP %s, fetching public IP...", ip)
		if pubIP, err := getPublicIP(); err == nil && pubIP != "" {
			return pubIP
		}
		log.Println("Failed to fetch public IP, using private IP")
	}

	return ip
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // Should not happen if coming from RemoteAddr
	}

	// Check for Loopback
	if ip.IsLoopback() {
		return true
	}

	// Check for Private Networks
	privateIPBlocks := []*net.IPNet{
		parseCIDR("10.0.0.0/8"),
		parseCIDR("172.16.0.0/12"),
		parseCIDR("192.168.0.0/16"),
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDR(s string) *net.IPNet {
	_, block, _ := net.ParseCIDR(s)
	return block
}

func getPublicIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(ip), nil
}

// Structs for Cloudflare API
type CFAccessPolicyResponse struct {
	Success bool          `json:"success"`
	Errors  []interface{} `json:"errors"`
	Result  struct {
		Name     string        `json:"name"`
		Decision string        `json:"decision"`
		Include  []interface{} `json:"include"`
		Exclude  []interface{} `json:"exclude"`
		Require  []interface{} `json:"require"`
	} `json:"result"`
}

type CFAccessPolicyUpdate struct {
	Name     string        `json:"name"`
	Decision string        `json:"decision"`
	Include  []interface{} `json:"include"`
	Exclude  []interface{} `json:"exclude"`
	Require  []interface{} `json:"require"`
}

// maskString masks sensitive strings for logging
func maskString(s string) string {
	if s == "" {
		return "(not set)"
	}
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// checkIPInCloudflarePolicy checks if an IP exists in the Cloudflare policy
func checkIPInCloudflarePolicy(ctx context.Context, ip string) error {
	if apiToken == "" || accountID == "" || policyID == "" {
		return fmt.Errorf("cloudflare credentials not configured")
	}

	res, err := cfRequest(ctx, "GET", fmt.Sprintf("access/policies/%s", policyID), nil)
	if err != nil {
		return err
	}

	for _, rule := range res.Result.Include {
		b, _ := json.Marshal(rule)
		if strings.Contains(string(b), fmt.Sprintf(`"ip":"%s"`, ip)) {
			return nil // Found
		}
	}

	return fmt.Errorf("IP not found in policy")
}

func cfRequest(ctx context.Context, method, path string, body interface{}) (*CFAccessPolicyResponse, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/%s", accountID, path)

	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res CFAccessPolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	if !res.Success {
		return nil, fmt.Errorf("CF API Error: %v", res.Errors)
	}
	return &res, nil
}

// addToCloudflareAccessPolicy adds the IP to a reusable Access Policy.
func addToCloudflareAccessPolicy(ctx context.Context, ip string) error {
	if apiToken == "" || accountID == "" || policyID == "" {
		log.Println("Skipping Cloudflare update: API credentials not configured")
		return nil
	}

	log.Printf("[Cloudflare] Attempting to add IP %s to policy %s", ip, policyID)

	// 1. Get Policy
	res, err := cfRequest(ctx, "GET", fmt.Sprintf("access/policies/%s", policyID), nil)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}
	policy := res.Result

	// 2. Check if exists
	exists := false
	for _, rule := range policy.Include {
		b, _ := json.Marshal(rule)
		if strings.Contains(string(b), fmt.Sprintf(`"ip":"%s"`, ip)) {
			exists = true
			break
		}
	}
	if exists {
		log.Printf("[Cloudflare] IP %s already exists in policy, skipping add", ip)
		return nil
	}

	// 3. Add IP
	newRule := map[string]interface{}{
		"ip": map[string]string{"ip": ip},
	}
	policy.Include = append(policy.Include, newRule)

	// 4. Update
	updatePayload := CFAccessPolicyUpdate{
		Name:     policy.Name,
		Decision: policy.Decision,
		Include:  policy.Include,
		Exclude:  policy.Exclude,
		Require:  policy.Require,
	}

	log.Printf("[Cloudflare] Sending PUT request to update policy")
	_, err = cfRequest(ctx, "PUT", fmt.Sprintf("access/policies/%s", policyID), updatePayload)
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	// 5. Verify the IP was added
	log.Printf("[Cloudflare] Verifying IP %s was added to policy", ip)
	verifyRes, err := cfRequest(ctx, "GET", fmt.Sprintf("access/policies/%s", policyID), nil)
	if err != nil {
		return fmt.Errorf("failed to verify policy update: %w", err)
	}

	verified := false
	for _, rule := range verifyRes.Result.Include {
		b, _ := json.Marshal(rule)
		if strings.Contains(string(b), fmt.Sprintf(`"ip":"%s"`, ip)) {
			verified = true
			break
		}
	}

	if !verified {
		return fmt.Errorf("verification failed: IP %s not found in policy after update", ip)
	}

	log.Printf("[Cloudflare] Successfully added and verified IP %s in policy", ip)
	return nil
}

func removeFromCloudflareAccessPolicy(ctx context.Context, ip string) error {
	if apiToken == "" || accountID == "" || policyID == "" {
		log.Println("Skipping Cloudflare removal: API credentials not configured")
		return nil
	}

	log.Printf("[Cloudflare] Attempting to remove IP %s from policy %s", ip, policyID)

	// 1. Get Policy
	res, err := cfRequest(ctx, "GET", fmt.Sprintf("access/policies/%s", policyID), nil)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}
	policy := res.Result

	// 2. Filter IP
	newIncludes := []interface{}{}
	removed := false
	for _, rule := range policy.Include {
		b, _ := json.Marshal(rule)
		s := string(b)
		// Check for ip or ip/32
		if strings.Contains(s, fmt.Sprintf(`"ip":"%s"`, ip)) || strings.Contains(s, fmt.Sprintf(`"ip":"%s/32"`, ip)) {
			removed = true
			log.Printf("[Cloudflare] Found IP %s in policy, removing", ip)
			continue
		}
		newIncludes = append(newIncludes, rule)
	}

	if !removed {
		log.Printf("[Cloudflare] IP %s not found in policy, nothing to remove", ip)
		return nil
	}

	// 3. Update
	updatePayload := CFAccessPolicyUpdate{
		Name:     policy.Name,
		Decision: policy.Decision,
		Include:  newIncludes,
		Exclude:  policy.Exclude,
		Require:  policy.Require,
	}

	log.Printf("[Cloudflare] Sending PUT request to remove IP from policy")
	_, err = cfRequest(ctx, "PUT", fmt.Sprintf("access/policies/%s", policyID), updatePayload)
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	// 4. Verify the IP was removed
	log.Printf("[Cloudflare] Verifying IP %s was removed from policy", ip)
	verifyRes, err := cfRequest(ctx, "GET", fmt.Sprintf("access/policies/%s", policyID), nil)
	if err != nil {
		return fmt.Errorf("failed to verify policy update: %w", err)
	}

	for _, rule := range verifyRes.Result.Include {
		b, _ := json.Marshal(rule)
		s := string(b)
		if strings.Contains(s, fmt.Sprintf(`"ip":"%s"`, ip)) || strings.Contains(s, fmt.Sprintf(`"ip":"%s/32"`, ip)) {
			return fmt.Errorf("verification failed: IP %s still found in policy after removal", ip)
		}
	}

	log.Printf("[Cloudflare] Successfully removed and verified IP %s from policy", ip)
	return nil
}

func startExpiryDaemon() {
	ticker := time.NewTicker(10 * time.Second)
	log.Println("Expiry daemon started")
	for range ticker.C {
		now := time.Now()

		// Snapshot entries to avoid long lock
		store.RLock()
		toRemove := []string{}
		for ip, expiry := range store.Entries {
			if now.After(expiry) {
				toRemove = append(toRemove, ip)
			}
		}
		store.RUnlock()

		for _, ip := range toRemove {
			log.Printf("Daemon: Removing expired IP %s", ip)
			if err := removeFromCloudflareAccessPolicy(context.Background(), ip); err != nil {
				log.Printf("Daemon: Error removing IP %s: %v", ip, err)
			} else {
				// Only remove from store if successfully removed from Cloudflare (or if error is not temporary?)
				// For this MVP, we remove from store to avoid loop.
			}
			store.Remove(ip)
		}
	}
}

// FileServer conveniently sets up a http.FileServer handler to serve
// static files from a http.FileSystem.
func FileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit any URL parameters.")
	}

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", 301).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
}
