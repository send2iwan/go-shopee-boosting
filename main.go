package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/nakagami/firebirdsql"
)

const (
	boostInterval = 4 * time.Hour // Interval waktu untuk boosting otomatis
	firebirdDSN   = "IWAN:070499@10.8.0.1:3050/rainbow"
	host          = "https://partner.shopeemobile.com"
	partnerID     = 2001198
	partnerKey    = "b8ce4238aa31839609421c5a089fac3bb40086784131946ce73768386ed140b7"
	code          = "c01204cada7b4cd0e4688154f5a256ca"
)

// Map alias untuk shop ID
var shopAlias = map[int]string{
	510526:    "SHP1",
	15114364:  "SHP2",
	95633757:  "SHP3",
	431165677: "SHP4",
	957116027: "SHP5",
	833596302: "SHP6",
	877734680: "SHP7",
}

// Map shop alias ke ID
var aliasToShopID = map[string]int{
	"SHP1": 510526,
	"SHP2": 15114364,
	"SHP3": 95633757,
	"SHP4": 431165677,
	"SHP5": 957116027,
	"SHP6": 833596302,
	"SHP7": 877734680,
}

// Fungsi untuk membaca itemIDList dari file boost.ini
func readBoostConfig(filename string) (map[int][]int64, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	shopItems := make(map[int][]int64)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "[") || len(line) == 0 {
			continue
		}

		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("Invalid format in config file")
		}

		shopID, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, err
		}

		itemIDStrs := strings.Split(parts[1], ",")
		var itemIDs []int64
		for _, itemIDStr := range itemIDStrs {
			itemID, err := strconv.ParseInt(strings.TrimSpace(itemIDStr), 10, 64)
			if err != nil {
				return nil, err
			}
			itemIDs = append(itemIDs, itemID)
		}

		shopItems[shopID] = itemIDs
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return shopItems, nil
}

// Fungsi untuk membaca token dari database Firebird
func readTokensFromDB(db *sql.DB) (map[int]map[string]string, error) {
	rows, err := db.Query("SELECT kdglobal, access_token, refresh_token FROM globalparams")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tokens := make(map[int]map[string]string)
	for rows.Next() {
		var shopAlias string
		var accessToken, refreshToken string
		if err := rows.Scan(&shopAlias, &accessToken, &refreshToken); err != nil {
			return nil, err
		}
		shopID, ok := aliasToShopID[shopAlias]
		if !ok {
			return nil, fmt.Errorf("Unknown shop alias: %s", shopAlias)
		}
		tokens[shopID] = map[string]string{
			"accessToken":  accessToken,
			"refreshToken": refreshToken,
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tokens, nil
}

// Fungsi untuk menyimpan token ke database Firebird
func writeTokensToDB(db *sql.DB, tokens map[int]map[string]string) error {
	for shopID, tokenData := range tokens {
		shopAlias := shopAlias[shopID]
		_, err := db.Exec("UPDATE OR INSERT INTO globalparams (kdglobal, access_token, refresh_token) VALUES (?, ?, ?)", shopAlias, tokenData["accessToken"], tokenData["refreshToken"])
		if err != nil {
			return err
		}
	}
	return nil
}

// Fungsi untuk membentuk tanda tangan (sign)
func generateSign(partnerID int, path string, timest int64, partnerKey string) string {
	baseString := fmt.Sprintf("%d%s%d", partnerID, path, timest)
	h := hmac.New(sha256.New, []byte(partnerKey))
	h.Write([]byte(baseString))
	return hex.EncodeToString(h.Sum(nil))
}

// Fungsi untuk membentuk tanda tangan (sign) dengan shop level
func generateSign4Shop(partnerID int, path string, timestamp int64, accessToken string, shopID int) string {
	baseString := fmt.Sprintf("%d%s%d%s%d", partnerID, path, timestamp, accessToken, shopID)
	h := hmac.New(sha256.New, []byte(partnerKey))
	h.Write([]byte(baseString))
	return hex.EncodeToString(h.Sum(nil))
}

// Fungsi untuk mendapatkan token shop level pertama kali
func getAccessToken(code string, partnerID int, partnerKey string, shopID int) (string, string, error) {
	timest := time.Now().Unix()
	path := "/api/v2/auth/token/get"
	body := map[string]interface{}{
		"code":       code,
		"shop_id":    shopID,
		"partner_id": partnerID,
	}

	sign := generateSign(partnerID, path, timest, partnerKey)
	url := fmt.Sprintf("%s%s?partner_id=%d&timestamp=%d&sign=%s", host, path, partnerID, timest, sign)

	jsonData, err := json.Marshal(body)
	if err != nil {
		return "", "", fmt.Errorf("Error marshalling JSON: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", "", fmt.Errorf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: time.Second * 10}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("Request failed with status: %v", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("Error decoding response: %v", err)
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		return "", "", fmt.Errorf("Error getting access token from response")
	}

	newRefreshToken, ok := result["refresh_token"].(string)
	if !ok {
		return "", "", fmt.Errorf("Error getting refresh token from response")
	}

	return accessToken, newRefreshToken, nil
}

// Fungsi untuk memperbarui token shop level
func refreshAccessToken(shopID, partnerID int, partnerKey, refreshToken string) (string, string, error) {
	timest := time.Now().Unix()
	path := "/api/v2/auth/access_token/get"
	body := map[string]interface{}{
		"shop_id":       shopID,
		"refresh_token": refreshToken,
		"partner_id":    partnerID,
	}

	sign := generateSign(partnerID, path, timest, partnerKey)
	url := fmt.Sprintf("%s%s?partner_id=%d&timestamp=%d&sign=%s", host, path, partnerID, timest, sign)

	jsonData, err := json.Marshal(body)
	if err != nil {
		return "", "", fmt.Errorf("Error marshalling JSON: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", "", fmt.Errorf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: time.Second * 10}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("Request failed with status: %v", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("Error decoding response: %v", err)
	}

	accessToken, ok := result["access_token"].(string)
	if !ok {
		return "", "", fmt.Errorf("Error getting access token from response")
	}

	newRefreshToken, ok := result["refresh_token"].(string)
	if !ok {
		return "", "", fmt.Errorf("Error getting refresh token from response")
	}

	return accessToken, newRefreshToken, nil
}

// Fungsi untuk melakukan boost item
func boostItem(shopID, partnerID int, partnerKey, accessToken string, itemIDList []int64) error {
	timest := time.Now().Unix()
	path := "/api/v2/product/boost_item"
	sign := generateSign4Shop(partnerID, path, timest, accessToken, shopID)
	url := fmt.Sprintf("%s%s?shop_id=%d&partner_id=%d&sign=%s&access_token=%s&timestamp=%d", host, path, shopID, partnerID, sign, accessToken, timest)

	body := map[string]interface{}{
		"item_id_list": itemIDList,
	}
	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("Error marshalling JSON: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: time.Second * 10}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Request failed with status: %v", resp.Status)
	}

	return nil
}

// Fungsi untuk worker yang akan menjalankan boosting item
func worker(id int, jobs <-chan int, results chan<- error, partnerID int, partnerKey, code string, shopItems map[int][]int64, tokens map[int]map[string]string, db *sql.DB) {
	for shopID := range jobs {
		alias := shopAlias[shopID]
		fmt.Printf("Worker %d: Processing shopID %d (alias: %s)\n", id, shopID, alias)
		itemIDList := shopItems[shopID]

		var accessToken, refreshToken string

		// Periksa apakah token sudah ada di database
		if tokenData, exists := tokens[shopID]; exists {
			accessToken = tokenData["accessToken"]
			refreshToken = tokenData["refreshToken"]
		} else {
			// Mendapatkan token shop level pertama kali dan simpan ke database
			var err error
			accessToken, refreshToken, err = getAccessToken(code, partnerID, partnerKey, shopID)
			if err != nil {
				fmt.Printf("Worker %d: Error getting shop level token for shopID %d (alias: %s): %v\n", id, shopID, alias, err)
				results <- err
				continue
			}
			tokens[shopID] = map[string]string{
				"accessToken":  accessToken,
				"refreshToken": refreshToken,
			}
			err = writeTokensToDB(db, tokens)
			if err != nil {
				fmt.Printf("Worker %d: Error writing tokens to DB for shopID %d (alias: %s): %v\n", id, shopID, alias, err)
				results <- err
				continue
			}
		}

		// Melakukan boost item
		if err := boostItem(shopID, partnerID, partnerKey, accessToken, itemIDList); err != nil {
			fmt.Printf("Worker %d: Error boosting item for shopID %d (alias: %s): %v\n", id, shopID, alias, err)
			results <- err
			continue
		}

		// Memperbarui access token shop level jika diperlukan
		newAccessToken, newRefreshToken, err := refreshAccessToken(shopID, partnerID, partnerKey, refreshToken)
		if err != nil {
			fmt.Printf("Worker %d: Error refreshing shop level token for shopID %d (alias: %s): %v\n", id, shopID, alias, err)
			results <- err
			continue
		}
		tokens[shopID]["accessToken"] = newAccessToken
		tokens[shopID]["refreshToken"] = newRefreshToken

		// Melakukan boost item dengan access token yang baru
		if err := boostItem(shopID, partnerID, partnerKey, newAccessToken, itemIDList); err != nil {
			fmt.Printf("Worker %d: Error boosting item with new access token for shopID %d (alias: %s): %v\n", id, shopID, alias, err)
			results <- err
			continue
		}

		results <- nil
	}
}

func boostItemsPeriodically() {
	for {
		// Membaca konfigurasi boost dari file
		shopItems, err := readBoostConfig("boost.ini")
		if err != nil {
			fmt.Println("Error reading boost config:", err)
			return
		}

		// Menghubungkan ke database Firebird
		db, err := sql.Open("firebirdsql", firebirdDSN)
		if err != nil {
			fmt.Println("Error connecting to Firebird:", err)
			return
		}
		defer db.Close()

		// Membaca token dari database
		tokens, err := readTokensFromDB(db)
		if err != nil {
			fmt.Println("Error reading tokens from DB:", err)
			return
		}

		// Membuat worker pool
		numWorkers := runtime.NumCPU()
		jobs := make(chan int, len(shopItems))
		results := make(chan error, len(shopItems))

		var wg sync.WaitGroup

		for w := 1; w <= numWorkers; w++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				worker(id, jobs, results, partnerID, partnerKey, code, shopItems, tokens, db)
			}(w)
		}

		// Mengirim pekerjaan ke worker
		for shopID := range shopItems {
			jobs <- shopID
		}
		close(jobs)

		// Menunggu semua hasil
		for i := 0; i < len(shopItems); i++ {
			<-results
		}

		// Menyimpan token ke database
		if err := writeTokensToDB(db, tokens); err != nil {
			fmt.Println("Error writing tokens to DB:", err)
		}

		fmt.Println("Boosting completed. Waiting for the next interval...")
		time.Sleep(boostInterval)
	}
}

func main() {
	go boostItemsPeriodically()

	select {} // Keep the main function running
}
