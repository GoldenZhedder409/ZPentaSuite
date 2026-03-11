package main

import (
    "bufio"
    "context"
    "crypto/md5"
    "database/sql"
    "encoding/json"
    "encoding/xml"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/signal"
    "path/filepath"
    "regexp"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/fatih/color"
    _ "github.com/mattn/go-sqlite3"
    "github.com/google/uuid"
    "github.com/joho/godotenv"
    "github.com/likexian/whois"
    "golang.org/x/time/rate"
    "gopkg.in/yaml.v3"
)

// ========== CONFIGURATION ==========

type Config struct {
    ShodanAPIKey     string        `yaml:"shodan_api_key" json:"shodan_api_key"`
    VirusTotalAPIKey string        `yaml:"virustotal_api_key" json:"virustotal_api_key"`
    HIBPAPIKey       string        `yaml:"hibp_api_key" json:"hibp_api_key"`
    MaxWorkers       int           `yaml:"max_workers" json:"max_workers"`
    CacheTTL         time.Duration `yaml:"cache_ttl" json:"cache_ttl"`
    RequestTimeout   time.Duration `yaml:"request_timeout" json:"request_timeout"`
    RateLimit        int           `yaml:"rate_limit" json:"rate_limit"`
    UserAgent        string        `yaml:"user_agent" json:"user_agent"`
    EnableCache      bool          `yaml:"enable_cache" json:"enable_cache"`
    MaxResults       int           `yaml:"max_results" json:"max_results"`
    DBPath           string        `yaml:"db_path" json:"db_path"`
}

func DefaultConfig() *Config {
    return &Config{
        MaxWorkers:       10,
        CacheTTL:         3600 * time.Second,
        RequestTimeout:   30 * time.Second,
        RateLimit:        20,
        UserAgent:        "Zenego/1.0 (Advanced OSINT Tool)",
        EnableCache:      true,
        MaxResults:       1000,
        DBPath:           "data/zenego.db",
    }
}

// ========== DATABASE ==========

type Entity struct {
    ID         string                 `json:"id"`
    Type       string                 `json:"type"`
    Value      string                 `json:"value"`
    Properties map[string]interface{} `json:"properties"`
    Source     string                 `json:"source"`
    CreatedAt  time.Time              `json:"created_at"`
}

type Relationship struct {
    ID           int                    `json:"id"`
    FromID       string                 `json:"from_id"`
    ToID         string                 `json:"to_id"`
    Relationship string                 `json:"relationship"`
    Properties   map[string]interface{} `json:"properties"`
    CreatedAt    time.Time              `json:"created_at"`
}

type GraphData struct {
    Entities      []Entity                 `json:"entities"`
    Relationships []Relationship           `json:"relationships"`
    Metadata      map[string]interface{}   `json:"metadata"`
}

type CacheItem struct {
    Key       string          `json:"key"`
    Value     json.RawMessage `json:"value"`
    ExpiresAt time.Time       `json:"expires_at"`
    CreatedAt time.Time       `json:"created_at"`
}

type Job struct {
    ID        string          `json:"id"`
    Type      string          `json:"type"`
    Input     string          `json:"input"`
    Status    string          `json:"status"`
    Progress  int             `json:"progress"`
    Result    json.RawMessage `json:"result"`
    Error     string          `json:"error"`
    CreatedAt time.Time       `json:"created_at"`
    UpdatedAt time.Time       `json:"updated_at"`
}

type ZenegoDB struct {
    db  *sql.DB
    mu  sync.RWMutex
    ctx context.Context
    cancel context.CancelFunc
}

func NewZenegoDB(config *Config) (*ZenegoDB, error) {
    // Ensure directory exists
    if err := os.MkdirAll(filepath.Dir(config.DBPath), 0755); err != nil {
        return nil, fmt.Errorf("failed to create data directory: %w", err)
    }

    // Open database with optimizations
    db, err := sql.Open("sqlite3", config.DBPath+
        "?_journal=WAL"+
        "&_timeout=5000"+
        "&_fk=true"+
        "&_synchronous=NORMAL"+
        "&_cache_size=10000")
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }

    // Configure connection pool
    db.SetMaxOpenConns(50)
    db.SetMaxIdleConns(10)
    db.SetConnMaxLifetime(10 * time.Minute)
    db.SetConnMaxIdleTime(5 * time.Minute)

    ctx, cancel := context.WithCancel(context.Background())
    
    zdb := &ZenegoDB{
        db:  db,
        ctx: ctx,
        cancel: cancel,
    }

    if err := zdb.createTables(); err != nil {
        return nil, err
    }

    if config.EnableCache {
        go zdb.cleanupCache(config.CacheTTL)
    }

    return zdb, nil
}

func (z *ZenegoDB) createTables() error {
    queries := []string{
        `CREATE TABLE IF NOT EXISTS entities (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            properties JSON,
            source TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(type, value)
        )`,
        `CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type)`,
        `CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(value)`,
        `CREATE INDEX IF NOT EXISTS idx_entities_source ON entities(source)`,
        `CREATE INDEX IF NOT EXISTS idx_entities_created ON entities(created_at)`,

        `CREATE TABLE IF NOT EXISTS relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_id TEXT NOT NULL,
            to_id TEXT NOT NULL,
            relationship TEXT,
            properties JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (from_id) REFERENCES entities(id) ON DELETE CASCADE,
            FOREIGN KEY (to_id) REFERENCES entities(id) ON DELETE CASCADE
        )`,
        `CREATE INDEX IF NOT EXISTS idx_relationships_from ON relationships(from_id)`,
        `CREATE INDEX IF NOT EXISTS idx_relationships_to ON relationships(to_id)`,
        `CREATE INDEX IF NOT EXISTS idx_relationships_type ON relationships(relationship)`,

        `CREATE TABLE IF NOT EXISTS cache (
            key TEXT PRIMARY KEY,
            value JSON,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache(expires_at)`,

        `CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            input TEXT NOT NULL,
            status TEXT,
            progress INT,
            result JSON,
            error TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
        `CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)`,
        `CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at)`,
    }

    for _, query := range queries {
        if _, err := z.db.Exec(query); err != nil {
            return fmt.Errorf("failed to create table: %w", err)
        }
    }

    return nil
}

func (z *ZenegoDB) cleanupCache(ttl time.Duration) {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            z.mu.Lock()
            _, err := z.db.Exec(`DELETE FROM cache WHERE expires_at < datetime('now')`)
            if err != nil {
                log.Printf("Cache cleanup error: %v", err)
            }
            z.mu.Unlock()
        case <-z.ctx.Done():
            return
        }
    }
}

func (z *ZenegoDB) SaveEntity(ctx context.Context, entityType, value, source string, properties map[string]interface{}) (string, error) {
    z.mu.Lock()
    defer z.mu.Unlock()

    // Generate ID
    hash := md5.Sum([]byte(fmt.Sprintf("%s:%s", entityType, value)))
    id := fmt.Sprintf("%x", hash[:])

    // Marshal properties
    propsJSON, err := json.Marshal(properties)
    if err != nil {
        return "", fmt.Errorf("failed to marshal properties: %w", err)
    }

    // Upsert entity
    _, err = z.db.ExecContext(ctx,
        `INSERT INTO entities (id, type, value, properties, source) 
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(type, value) DO UPDATE SET
            properties = json_patch(properties, excluded.properties),
            source = excluded.source,
            created_at = CURRENT_TIMESTAMP`,
        id, entityType, value, string(propsJSON), source)

    if err != nil {
        return "", fmt.Errorf("failed to save entity: %w", err)
    }

    return id, nil
}

func (z *ZenegoDB) SaveEntityBatch(ctx context.Context, entities []map[string]interface{}) ([]string, error) {
    if len(entities) == 0 {
        return nil, nil
    }

    z.mu.Lock()
    defer z.mu.Unlock()

    tx, err := z.db.BeginTx(ctx, nil)
    if err != nil {
        return nil, err
    }
    defer tx.Rollback()

    stmt, err := tx.PrepareContext(ctx,
        `INSERT INTO entities (id, type, value, properties, source) 
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(type, value) DO UPDATE SET
            properties = json_patch(properties, excluded.properties),
            source = excluded.source,
            created_at = CURRENT_TIMESTAMP`)
    if err != nil {
        return nil, err
    }
    defer stmt.Close()

    var ids []string
    for _, entity := range entities {
        entityType, _ := entity["type"].(string)
        value, _ := entity["value"].(string)
        source, _ := entity["source"].(string)
        props, _ := entity["properties"].(map[string]interface{})

        if entityType == "" || value == "" {
            continue
        }

        hash := md5.Sum([]byte(fmt.Sprintf("%s:%s", entityType, value)))
        id := fmt.Sprintf("%x", hash[:])

        propsJSON, err := json.Marshal(props)
        if err != nil {
            continue
        }

        _, err = stmt.ExecContext(ctx, id, entityType, value, string(propsJSON), source)
        if err != nil {
            return nil, err
        }

        ids = append(ids, id)
    }

    if err := tx.Commit(); err != nil {
        return nil, err
    }

    return ids, nil
}

func (z *ZenegoDB) SaveRelationship(ctx context.Context, fromID, toID, relationship string, properties map[string]interface{}) error {
    z.mu.Lock()
    defer z.mu.Unlock()

    propsJSON, err := json.Marshal(properties)
    if err != nil {
        return fmt.Errorf("failed to marshal relationship properties: %w", err)
    }

    _, err = z.db.ExecContext(ctx,
        `INSERT INTO relationships (from_id, to_id, relationship, properties)
        VALUES (?, ?, ?, ?)`,
        fromID, toID, relationship, string(propsJSON))

    return err
}

func (z *ZenegoDB) SaveRelationshipBatch(ctx context.Context, relationships []map[string]interface{}) error {
    if len(relationships) == 0 {
        return nil
    }

    z.mu.Lock()
    defer z.mu.Unlock()

    tx, err := z.db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    stmt, err := tx.PrepareContext(ctx,
        `INSERT INTO relationships (from_id, to_id, relationship, properties)
        VALUES (?, ?, ?, ?)`)
    if err != nil {
        return err
    }
    defer stmt.Close()

    for _, rel := range relationships {
        fromID, _ := rel["from_id"].(string)
        toID, _ := rel["to_id"].(string)
        relType, _ := rel["relationship"].(string)
        props, _ := rel["properties"].(map[string]interface{})

        if fromID == "" || toID == "" {
            continue
        }

        propsJSON, err := json.Marshal(props)
        if err != nil {
            continue
        }

        _, err = stmt.ExecContext(ctx, fromID, toID, relType, string(propsJSON))
        if err != nil {
            return err
        }
    }

    return tx.Commit()
}

func (z *ZenegoDB) GetCache(ctx context.Context, key string) (json.RawMessage, error) {
    z.mu.RLock()
    defer z.mu.RUnlock()

    var value json.RawMessage
    err := z.db.QueryRowContext(ctx,
        `SELECT value FROM cache 
        WHERE key = ? AND (expires_at > datetime('now') OR expires_at IS NULL)`,
        key).Scan(&value)

    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }

    return value, nil
}

func (z *ZenegoDB) SetCache(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
    z.mu.Lock()
    defer z.mu.Unlock()

    data, err := json.Marshal(value)
    if err != nil {
        return err
    }

    expiresAt := time.Now().Add(ttl)

    _, err = z.db.ExecContext(ctx,
        `INSERT OR REPLACE INTO cache (key, value, expires_at)
        VALUES (?, ?, ?)`,
        key, string(data), expiresAt)

    return err
}

func (z *ZenegoDB) Search(ctx context.Context, query string, entityType string, limit, offset int) ([]Entity, int, error) {
    var rows *sql.Rows
    var err error
    var total int

    // Get total count
    if entityType != "" {
        err = z.db.QueryRowContext(ctx,
            `SELECT COUNT(*) FROM entities WHERE value LIKE ? AND type = ?`,
            "%"+query+"%", entityType).Scan(&total)
    } else {
        err = z.db.QueryRowContext(ctx,
            `SELECT COUNT(*) FROM entities WHERE value LIKE ?`,
            "%"+query+"%").Scan(&total)
    }
    if err != nil {
        return nil, 0, err
    }

    // Get paginated results
    if entityType != "" {
        rows, err = z.db.QueryContext(ctx,
            `SELECT id, type, value, properties, source, created_at 
            FROM entities 
            WHERE value LIKE ? AND type = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?`,
            "%"+query+"%", entityType, limit, offset)
    } else {
        rows, err = z.db.QueryContext(ctx,
            `SELECT id, type, value, properties, source, created_at 
            FROM entities 
            WHERE value LIKE ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?`,
            "%"+query+"%", limit, offset)
    }

    if err != nil {
        return nil, 0, err
    }
    defer rows.Close()

    var entities []Entity
    for rows.Next() {
        var e Entity
        var propsJSON string
        var createdStr string
        if err := rows.Scan(&e.ID, &e.Type, &e.Value, &propsJSON, &e.Source, &createdStr); err != nil {
            return nil, 0, err
        }
        e.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
        
        if err := json.Unmarshal([]byte(propsJSON), &e.Properties); err != nil {
            e.Properties = make(map[string]interface{})
        }
        
        entities = append(entities, e)
    }

    return entities, total, nil
}

func (z *ZenegoDB) GetEntity(ctx context.Context, id string) (*Entity, error) {
    var e Entity
    var propsJSON string
    var createdStr string

    err := z.db.QueryRowContext(ctx,
        `SELECT id, type, value, properties, source, created_at 
        FROM entities WHERE id = ?`, id).
        Scan(&e.ID, &e.Type, &e.Value, &propsJSON, &e.Source, &createdStr)

    if err != nil {
        return nil, err
    }

    e.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
    if err := json.Unmarshal([]byte(propsJSON), &e.Properties); err != nil {
        e.Properties = make(map[string]interface{})
    }

    return &e, nil
}

func (z *ZenegoDB) GetRelationships(ctx context.Context, entityID string, direction string) ([]Relationship, error) {
    var query string
    var args []interface{}

    switch direction {
    case "in":
        query = `SELECT id, from_id, to_id, relationship, properties, created_at 
                FROM relationships WHERE to_id = ?`
        args = []interface{}{entityID}
    case "out":
        query = `SELECT id, from_id, to_id, relationship, properties, created_at 
                FROM relationships WHERE from_id = ?`
        args = []interface{}{entityID}
    default:
        query = `SELECT id, from_id, to_id, relationship, properties, created_at 
                FROM relationships WHERE from_id = ? OR to_id = ?`
        args = []interface{}{entityID, entityID}
    }

    rows, err := z.db.QueryContext(ctx, query, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var relationships []Relationship
    for rows.Next() {
        var r Relationship
        var propsJSON string
        var createdStr string

        if err := rows.Scan(&r.ID, &r.FromID, &r.ToID, &r.Relationship, &propsJSON, &createdStr); err != nil {
            return nil, err
        }

        r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
        if err := json.Unmarshal([]byte(propsJSON), &r.Properties); err != nil {
            r.Properties = make(map[string]interface{})
        }

        relationships = append(relationships, r)
    }

    return relationships, nil
}

func (z *ZenegoDB) GetGraph(ctx context.Context, startID string, depth int, limit int) (*GraphData, error) {
    var entities []Entity
    var relationships []Relationship
    entityMap := make(map[string]bool)

    if startID != "" && depth > 0 {
        // BFS approach for graph traversal
        queue := []string{startID}
        visited := make(map[string]int)
        visited[startID] = 0

        for len(queue) > 0 && len(entities) < limit {
            currentID := queue[0]
            queue = queue[1:]
            currentDepth := visited[currentID]

            // Get entity
            entity, err := z.GetEntity(ctx, currentID)
            if err == nil && !entityMap[currentID] {
                entities = append(entities, *entity)
                entityMap[currentID] = true
            }

            if currentDepth < depth {
                // Get relationships
                rels, err := z.GetRelationships(ctx, currentID, "both")
                if err == nil {
                    for _, rel := range rels {
                        // Add relationship if not already added
                        found := false
                        for _, r := range relationships {
                            if r.ID == rel.ID {
                                found = true
                                break
                            }
                        }
                        if !found {
                            relationships = append(relationships, rel)
                        }

                        // Queue neighbor
                        neighborID := rel.FromID
                        if neighborID == currentID {
                            neighborID = rel.ToID
                        }

                        if _, ok := visited[neighborID]; !ok && len(entities) < limit {
                            visited[neighborID] = currentDepth + 1
                            queue = append(queue, neighborID)
                        }
                    }
                }
            }
        }
    } else {
        // Get recent entities
        rows, err := z.db.QueryContext(ctx,
            `SELECT id, type, value, properties, source, created_at 
            FROM entities 
            ORDER BY created_at DESC 
            LIMIT ?`, limit)
        if err != nil {
            return nil, err
        }
        defer rows.Close()

        for rows.Next() {
            var e Entity
            var propsJSON string
            var createdStr string

            if err := rows.Scan(&e.ID, &e.Type, &e.Value, &propsJSON, &e.Source, &createdStr); err != nil {
                return nil, err
            }

            e.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
            if err := json.Unmarshal([]byte(propsJSON), &e.Properties); err != nil {
                e.Properties = make(map[string]interface{})
            }

            entities = append(entities, e)
            entityMap[e.ID] = true
        }

        // Get relationships for these entities
        if len(entities) > 0 {
            ids := make([]interface{}, len(entities))
            placeholders := make([]string, len(entities))
            for i, e := range entities {
                ids[i] = e.ID
                placeholders[i] = "?"
            }

            query := fmt.Sprintf(
                `SELECT id, from_id, to_id, relationship, properties, created_at 
                FROM relationships 
                WHERE from_id IN (%s) AND to_id IN (%s)`,
                strings.Join(placeholders, ","),
                strings.Join(placeholders, ","))

            relRows, err := z.db.QueryContext(ctx, query, append(ids, ids...)...)
            if err != nil {
                return nil, err
            }
            defer relRows.Close()

            for relRows.Next() {
                var r Relationship
                var propsJSON string
                var createdStr string

                if err := relRows.Scan(&r.ID, &r.FromID, &r.ToID, &r.Relationship, &propsJSON, &createdStr); err != nil {
                    return nil, err
                }

                r.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
                if err := json.Unmarshal([]byte(propsJSON), &r.Properties); err != nil {
                    r.Properties = make(map[string]interface{})
                }

                relationships = append(relationships, r)
            }
        }
    }

    metadata := map[string]interface{}{
        "total_entities":      len(entities),
        "total_relationships": len(relationships),
        "generated_at":        time.Now(),
        "start_id":            startID,
        "depth":               depth,
    }

    return &GraphData{
        Entities:      entities,
        Relationships: relationships,
        Metadata:      metadata,
    }, nil
}

func (z *ZenegoDB) CreateJob(ctx context.Context, jobType, input string) (string, error) {
    z.mu.Lock()
    defer z.mu.Unlock()

    id := uuid.New().String()
    _, err := z.db.ExecContext(ctx,
        `INSERT INTO jobs (id, type, input, status, progress)
        VALUES (?, ?, ?, 'pending', 0)`,
        id, jobType, input)

    if err != nil {
        return "", err
    }

    return id, nil
}

func (z *ZenegoDB) UpdateJob(ctx context.Context, id, status string, progress int, result interface{}, errMsg string) error {
    z.mu.Lock()
    defer z.mu.Unlock()

    var resultJSON []byte
    var err error

    if result != nil {
        resultJSON, err = json.Marshal(result)
        if err != nil {
            return err
        }
    }

    _, err = z.db.ExecContext(ctx,
        `UPDATE jobs 
        SET status = ?, progress = ?, result = ?, error = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?`,
        status, progress, string(resultJSON), errMsg, id)

    return err
}

func (z *ZenegoDB) GetJob(ctx context.Context, id string) (*Job, error) {
    var j Job
    var resultStr, errorStr sql.NullString
    var createdStr, updatedStr string

    err := z.db.QueryRowContext(ctx,
        `SELECT id, type, input, status, progress, result, error, created_at, updated_at 
        FROM jobs WHERE id = ?`, id).
        Scan(&j.ID, &j.Type, &j.Input, &j.Status, &j.Progress, &resultStr, &errorStr, &createdStr, &updatedStr)

    if err != nil {
        return nil, err
    }

    j.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
    j.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedStr)

    if resultStr.Valid {
        j.Result = json.RawMessage(resultStr.String)
    }
    if errorStr.Valid {
        j.Error = errorStr.String
    }

    return &j, nil
}

func (z *ZenegoDB) ListJobs(ctx context.Context, status string, limit, offset int) ([]Job, int, error) {
    var rows *sql.Rows
    var err error
    var total int

    // Get total count
    if status != "" {
        err = z.db.QueryRowContext(ctx,
            `SELECT COUNT(*) FROM jobs WHERE status = ?`, status).Scan(&total)
    } else {
        err = z.db.QueryRowContext(ctx,
            `SELECT COUNT(*) FROM jobs`).Scan(&total)
    }
    if err != nil {
        return nil, 0, err
    }

    // Get paginated results
    if status != "" {
        rows, err = z.db.QueryContext(ctx,
            `SELECT id, type, input, status, progress, result, error, created_at, updated_at 
            FROM jobs WHERE status = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?`,
            status, limit, offset)
    } else {
        rows, err = z.db.QueryContext(ctx,
            `SELECT id, type, input, status, progress, result, error, created_at, updated_at 
            FROM jobs
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?`,
            limit, offset)
    }

    if err != nil {
        return nil, 0, err
    }
    defer rows.Close()

    var jobs []Job
    for rows.Next() {
        var j Job
        var resultStr, errorStr sql.NullString
        var createdStr, updatedStr string

        if err := rows.Scan(&j.ID, &j.Type, &j.Input, &j.Status, &j.Progress,
            &resultStr, &errorStr, &createdStr, &updatedStr); err != nil {
            return nil, 0, err
        }

        j.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdStr)
        j.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedStr)

        if resultStr.Valid {
            j.Result = json.RawMessage(resultStr.String)
        }
        if errorStr.Valid {
            j.Error = errorStr.String
        }

        jobs = append(jobs, j)
    }

    return jobs, total, nil
}

func (z *ZenegoDB) GetStats(ctx context.Context) (map[string]interface{}, error) {
    stats := make(map[string]interface{})

    // Entity counts by type
    rows, err := z.db.QueryContext(ctx,
        `SELECT type, COUNT(*) as count FROM entities GROUP BY type ORDER BY count DESC`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    typeCounts := make(map[string]int)
    for rows.Next() {
        var typ string
        var count int
        if err := rows.Scan(&typ, &count); err == nil {
            typeCounts[typ] = count
        }
    }
    stats["entities_by_type"] = typeCounts

    // Source counts
    rows, err = z.db.QueryContext(ctx,
        `SELECT source, COUNT(*) as count FROM entities GROUP BY source ORDER BY count DESC`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    sourceCounts := make(map[string]int)
    for rows.Next() {
        var source string
        var count int
        if err := rows.Scan(&source, &count); err == nil {
            sourceCounts[source] = count
        }
    }
    stats["entities_by_source"] = sourceCounts

    // Total counts
    var totalEntities, totalRelationships, totalJobs int
    z.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entities`).Scan(&totalEntities)
    z.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM relationships`).Scan(&totalRelationships)
    z.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs`).Scan(&totalJobs)

    stats["total_entities"] = totalEntities
    stats["total_relationships"] = totalRelationships
    stats["total_jobs"] = totalJobs
    stats["database_size"] = z.getDBSize()
    stats["last_updated"] = time.Now()

    return stats, nil
}

func (z *ZenegoDB) getDBSize() int64 {
    var size int64
    z.db.QueryRow(`SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()`).Scan(&size)
    return size
}

func (z *ZenegoDB) Close() error {
    z.cancel()
    return z.db.Close()
}

// ========== API CLIENTS ==========

type APIClients struct {
    config       *Config
    httpClient   *http.Client
    rateLimiter  *rate.Limiter
    mu           sync.RWMutex
    sessionToken string
}

func NewAPIClients(config *Config) *APIClients {
    return &APIClients{
        config: config,
        httpClient: &http.Client{
            Timeout: config.RequestTimeout,
            Transport: &http.Transport{
                MaxIdleConns:        100,
                MaxIdleConnsPerHost: 20,
                IdleConnTimeout:     90 * time.Second,
                TLSHandshakeTimeout: 10 * time.Second,
                DisableCompression:  false,
                DisableKeepAlives:   false,
            },
        },
        rateLimiter:  rate.NewLimiter(rate.Limit(config.RateLimit), config.RateLimit),
        sessionToken: uuid.New().String(),
    }
}

func (c *APIClients) doRequest(ctx context.Context, method, urlStr string, headers map[string]string, body io.Reader) (*http.Response, error) {
    // Apply rate limiting
    if err := c.rateLimiter.Wait(ctx); err != nil {
        return nil, err
    }

    req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
    if err != nil {
        return nil, err
    }

    // Set default headers
    req.Header.Set("User-Agent", c.config.UserAgent)
    req.Header.Set("Accept", "application/json")
    req.Header.Set("X-Session-ID", c.sessionToken)

    if body != nil {
        req.Header.Set("Content-Type", "application/json")
    }

    // Set custom headers
    for k, v := range headers {
        req.Header.Set(k, v)
    }

    return c.httpClient.Do(req)
}

type ShodanMatch struct {
    IPStr     string `json:"ip_str"`
    Port      int    `json:"port"`
    Org       string `json:"org"`
    ISP       string `json:"isp"`
    OS        string `json:"os"`
    Hostnames []string `json:"hostnames"`
    Domains   []string `json:"domains"`
    Timestamp string `json:"timestamp"`
    Data      []struct {
        Shodan struct {
            Module string `json:"module"`
        } `json:"_shodan"`
    } `json:"data"`
    Location struct {
        CountryName string  `json:"country_name"`
        CountryCode string  `json:"country_code"`
        City        string  `json:"city"`
        Latitude    float64 `json:"latitude"`
        Longitude   float64 `json:"longitude"`
    } `json:"location"`
    Vulns []string `json:"vulns"`
    Tags  []string `json:"tags"`
}

type ShodanResponse struct {
    Matches []ShodanMatch `json:"matches"`
    Total   int           `json:"total"`
    Query   string        `json:"query"`
}

type TransformResult struct {
    Success       bool                      `json:"success"`
    Count         int                       `json:"count"`
    Entities      []map[string]interface{}  `json:"entities,omitempty"`
    Relationships []map[string]interface{}  `json:"relationships,omitempty"`
    Error         string                    `json:"error,omitempty"`
    Duration      time.Duration             `json:"duration"`
    Timestamp     time.Time                 `json:"timestamp"`
}

func (c *APIClients) ShodanSearch(ctx context.Context, query string) (*TransformResult, error) {
    if c.config.ShodanAPIKey == "" {
        return nil, fmt.Errorf("shodan API key not configured")
    }

    startTime := time.Now()

    urlStr := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&limit=100",
        c.config.ShodanAPIKey, url.QueryEscape(query))

    resp, err := c.doRequest(ctx, "GET", urlStr, nil, nil)
    if err != nil {
        return nil, fmt.Errorf("shodan request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("shodan API error: %s - %s", resp.Status, string(body))
    }

    var shodanResp ShodanResponse
    if err := json.NewDecoder(resp.Body).Decode(&shodanResp); err != nil {
        return nil, fmt.Errorf("failed to decode shodan response: %w", err)
    }

    // Process matches concurrently
    entityChan := make(chan map[string]interface{}, len(shodanResp.Matches)*5)
    relChan := make(chan map[string]interface{}, len(shodanResp.Matches)*10)
    var wg sync.WaitGroup

    workerCount := c.config.MaxWorkers
    if workerCount > len(shodanResp.Matches) {
        workerCount = len(shodanResp.Matches)
    }

    for i := 0; i < workerCount; i++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            for idx := workerID; idx < len(shodanResp.Matches); idx += workerCount {
                match := shodanResp.Matches[idx]

                // Generate IDs for relationships
                ipHash := md5.Sum([]byte(fmt.Sprintf("ip:%s", match.IPStr)))
                ipID := fmt.Sprintf("%x", ipHash[:])

                // IP Entity
                entityChan <- map[string]interface{}{
                    "type":   "ip",
                    "value":  match.IPStr,
                    "source": "shodan",
                    "properties": map[string]interface{}{
                        "country":      match.Location.CountryName,
                        "country_code": match.Location.CountryCode,
                        "city":         match.Location.City,
                        "latitude":     match.Location.Latitude,
                        "longitude":    match.Location.Longitude,
                        "org":          match.Org,
                        "isp":          match.ISP,
                        "os":           match.OS,
                        "hostnames":    match.Hostnames,
                        "domains":      match.Domains,
                        "vulns":        match.Vulns,
                        "tags":         match.Tags,
                        "timestamp":    match.Timestamp,
                    },
                }

                // Port Entity and relationship
                portHash := md5.Sum([]byte(fmt.Sprintf("port:%d:%s", match.Port, match.IPStr)))
                portID := fmt.Sprintf("%x", portHash[:])

                entityChan <- map[string]interface{}{
                    "type":   "port",
                    "value":  fmt.Sprintf("%d", match.Port),
                    "source": "shodan",
                    "properties": map[string]interface{}{
                        "ip":      match.IPStr,
                        "service": match.Data[0].Shodan.Module,
                        "port":    match.Port,
                    },
                }

                relChan <- map[string]interface{}{
                    "from_id":      ipID,
                    "to_id":        portID,
                    "relationship": "has_port",
                    "properties": map[string]interface{}{
                        "service": match.Data[0].Shodan.Module,
                        "port":    match.Port,
                        "source":  "shodan",
                    },
                }

                // Hostname entities and relationships
                for _, hostname := range match.Hostnames {
                    if hostname != "" {
                        hostHash := md5.Sum([]byte(fmt.Sprintf("hostname:%s", hostname)))
                        hostID := fmt.Sprintf("%x", hostHash[:])

                        entityChan <- map[string]interface{}{
                            "type":   "hostname",
                            "value":  hostname,
                            "source": "shodan",
                            "properties": map[string]interface{}{
                                "ip": match.IPStr,
                            },
                        }

                        relChan <- map[string]interface{}{
                            "from_id":      hostID,
                            "to_id":        ipID,
                            "relationship": "resolves_to",
                            "properties": map[string]interface{}{
                                "source": "shodan",
                            },
                        }
                    }
                }

                // Vulnerability entities
                for _, vuln := range match.Vulns {
                    vulnHash := md5.Sum([]byte(fmt.Sprintf("vuln:%s", vuln)))
                    vulnID := fmt.Sprintf("%x", vulnHash[:])

                    entityChan <- map[string]interface{}{
                        "type":   "vulnerability",
                        "value":  vuln,
                        "source": "shodan",
                        "properties": map[string]interface{}{
                            "ip":   match.IPStr,
                            "port": match.Port,
                        },
                    }

                    relChan <- map[string]interface{}{
                        "from_id":      ipID,
                        "to_id":        vulnID,
                        "relationship": "has_vulnerability",
                        "properties": map[string]interface{}{
                            "port":   match.Port,
                            "source": "shodan",
                        },
                    }
                }
            }
        }(i)
    }

    // Close channels when all workers done
    go func() {
        wg.Wait()
        close(entityChan)
        close(relChan)
    }()

    // Collect results
    var entities []map[string]interface{}
    var relationships []map[string]interface{}

    for entity := range entityChan {
        entities = append(entities, entity)
    }
    for rel := range relChan {
        relationships = append(relationships, rel)
    }

    duration := time.Since(startTime)

    return &TransformResult{
        Success:       true,
        Count:         len(entities),
        Entities:      entities,
        Relationships: relationships,
        Duration:      duration,
        Timestamp:     time.Now(),
    }, nil
}

func (c *APIClients) DNSLookup(ctx context.Context, domain string) (*TransformResult, error) {
    startTime := time.Now()
    
    var entities []map[string]interface{}
    var relationships []map[string]interface{}
    var mu sync.Mutex
    var wg sync.WaitGroup

    // Clean domain
    domain = strings.TrimSpace(strings.ToLower(domain))
    domain = strings.TrimPrefix(domain, "http://")
    domain = strings.TrimPrefix(domain, "https://")
    domain = strings.Split(domain, "/")[0]
    domain = strings.Split(domain, ":")[0]

    // Generate domain ID
    domainHash := md5.Sum([]byte(fmt.Sprintf("domain:%s", domain)))
    domainID := fmt.Sprintf("%x", domainHash[:])

    // Domain entity
    mu.Lock()
    entities = append(entities, map[string]interface{}{
        "type":       "domain",
        "value":      domain,
        "source":     "dns",
        "properties": map[string]interface{}{},
    })
    mu.Unlock()

    // DNS Record types to query
    recordTypes := []struct {
        name string
        fn   func(string) ([]string, error)
        rel  string
    }{
        {"a", func(d string) ([]string, error) {
            ips, err := net.LookupHost(d)
            if err != nil {
                return nil, err
            }
            return ips, nil
        }, "resolves_to"},
        {"mx", func(d string) ([]string, error) {
            mx, err := net.LookupMX(d)
            if err != nil {
                return nil, err
            }
            var result []string
            for _, m := range mx {
                result = append(result, fmt.Sprintf("%s:%d", m.Host, m.Pref))
            }
            return result, nil
        }, "has_mx"},
        {"ns", func(d string) ([]string, error) {
            ns, err := net.LookupNS(d)
            if err != nil {
                return nil, err
            }
            var result []string
            for _, n := range ns {
                result = append(result, n.Host)
            }
            return result, nil
        }, "has_ns"},
        {"txt", func(d string) ([]string, error) {
            txt, err := net.LookupTXT(d)
            if err != nil {
                return nil, err
            }
            return txt, nil
        }, "has_txt"},
        {"cname", func(d string) ([]string, error) {
            cname, err := net.LookupCNAME(d)
            if err != nil {
                return nil, err
            }
            return []string{cname}, nil
        }, "is_cname_of"},
    }

    for _, rt := range recordTypes {
        wg.Add(1)
        go func(recordType struct {
            name string
            fn   func(string) ([]string, error)
            rel  string
        }) {
            defer wg.Done()

            results, err := recordType.fn(domain)
            if err != nil {
                return
            }

            mu.Lock()
            defer mu.Unlock()

            for _, result := range results {
                // Create entity
                entityType := recordType.name
                if recordType.name == "a" {
                    entityType = "ip"
                }

                entityHash := md5.Sum([]byte(fmt.Sprintf("%s:%s", entityType, result)))
                entityID := fmt.Sprintf("%x", entityHash[:])

                entities = append(entities, map[string]interface{}{
                    "type":   entityType,
                    "value":  result,
                    "source": "dns",
                    "properties": map[string]interface{}{
                        "domain": domain,
                        "record": recordType.name,
                    },
                })

                // Create relationship
                relationships = append(relationships, map[string]interface{}{
                    "from_id":      domainID,
                    "to_id":        entityID,
                    "relationship": recordType.rel,
                    "properties": map[string]interface{}{
                        "record_type": recordType.name,
                        "source":      "dns",
                    },
                })
            }
        }(rt)
    }

    wg.Wait()

    duration := time.Since(startTime)

    return &TransformResult{
        Success:       true,
        Count:         len(entities),
        Entities:      entities,
        Relationships: relationships,
        Duration:      duration,
        Timestamp:     time.Now(),
    }, nil
}

func (c *APIClients) WHOISLookup(ctx context.Context, domain string) (*TransformResult, error) {
    startTime := time.Now()

    // Clean domain
    domain = strings.TrimSpace(strings.ToLower(domain))
    domain = strings.TrimPrefix(domain, "http://")
    domain = strings.TrimPrefix(domain, "https://")
    domain = strings.Split(domain, "/")[0]
    domain = strings.Split(domain, ":")[0]

    // WHOIS query with timeout
    type whoisResult struct {
        data string
        err  error
    }
    resultChan := make(chan whoisResult, 1)

    go func() {
        data, err := whois.Whois(domain)
        resultChan <- whoisResult{data, err}
    }()

    var whoisData string
    select {
    case res := <-resultChan:
        if res.err != nil {
            return nil, fmt.Errorf("whois lookup failed: %w", res.err)
        }
        whoisData = res.data
    case <-ctx.Done():
        return nil, ctx.Err()
    }

    // Parse WHOIS data
    domainHash := md5.Sum([]byte(fmt.Sprintf("domain:%s", domain)))
    domainID := fmt.Sprintf("%x", domainHash[:])

    entities := []map[string]interface{}{
        {
            "type":   "domain",
            "value":  domain,
            "source": "whois",
            "properties": map[string]interface{}{
                "raw_whois": whoisData,
            },
        },
    }

    var relationships []map[string]interface{}

    // Extract information using regex
    patterns := map[string]*regexp.Regexp{
        "registrar":  regexp.MustCompile(`(?i)registrar:\s*(.+)`),
        "creation":   regexp.MustCompile(`(?i)creation\s*date:\s*(.+)`),
        "expiry":     regexp.MustCompile(`(?i)registry\s*expiry\s*date:\s*(.+)|expir.+date:\s*(.+)`),
        "updated":    regexp.MustCompile(`(?i)updated\s*date:\s*(.+)|last\s*updated:\s*(.+)`),
        "nameserver": regexp.MustCompile(`(?i)name\s*server:\s*(\S+)`),
        "status":     regexp.MustCompile(`(?i)domain\s*status:\s*(.+)`),
        "dnssec":     regexp.MustCompile(`(?i)dnssec:\s*(.+)`),
        "org":        regexp.MustCompile(`(?i)registrant\s*organization:\s*(.+)|org:\s*(.+)`),
        "email":      regexp.MustCompile(`(?i)registrar\s*abuse\s*contact\s*email:\s*(.+)|email:\s*(.+)`),
    }

    properties := make(map[string]interface{})
    
    for key, pattern := range patterns {
        matches := pattern.FindStringSubmatch(whoisData)
        if len(matches) > 1 {
            for i := 1; i < len(matches); i++ {
                if matches[i] != "" {
                    properties[key] = strings.TrimSpace(matches[i])
                    break
                }
            }
        }
    }

    // Update domain properties
    entities[0]["properties"] = properties

    // Extract and create entities for nameservers
    if nsMatches := patterns["nameserver"].FindAllStringSubmatch(whoisData, -1); len(nsMatches) > 0 {
        for _, match := range nsMatches {
            if len(match) > 1 && match[1] != "" {
                ns := strings.TrimSpace(strings.ToLower(match[1]))
                nsHash := md5.Sum([]byte(fmt.Sprintf("nameserver:%s", ns)))
                nsID := fmt.Sprintf("%x", nsHash[:])

                entities = append(entities, map[string]interface{}{
                    "type":   "nameserver",
                    "value":  ns,
                    "source": "whois",
                    "properties": map[string]interface{}{
                        "domain": domain,
                    },
                })

                relationships = append(relationships, map[string]interface{}{
                    "from_id":      domainID,
                    "to_id":        nsID,
                    "relationship": "has_nameserver",
                    "properties": map[string]interface{}{
                        "source": "whois",
                    },
                })
            }
        }
    }

    // Registrar entity
    if registrar, ok := properties["registrar"].(string); ok && registrar != "" {
        regHash := md5.Sum([]byte(fmt.Sprintf("registrar:%s", registrar)))
        regID := fmt.Sprintf("%x", regHash[:])

        entities = append(entities, map[string]interface{}{
            "type":       "registrar",
            "value":      registrar,
            "source":     "whois",
            "properties": map[string]interface{}{},
        })

        relationships = append(relationships, map[string]interface{}{
            "from_id":      domainID,
            "to_id":        regID,
            "relationship": "registered_with",
            "properties": map[string]interface{}{
                "source": "whois",
            },
        })
    }

    duration := time.Since(startTime)

    return &TransformResult{
        Success:       true,
        Count:         len(entities),
        Entities:      entities,
        Relationships: relationships,
        Duration:      duration,
        Timestamp:     time.Now(),
    }, nil
}

func (c *APIClients) IPInfoLookup(ctx context.Context, ip string) (*TransformResult, error) {
    startTime := time.Now()

    // Validate IP
    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return nil, fmt.Errorf("invalid IP address: %s", ip)
    }

    ipHash := md5.Sum([]byte(fmt.Sprintf("ip:%s", ip)))
    ipID := fmt.Sprintf("%x", ipHash[:])

    entities := []map[string]interface{}{
        {
            "type":   "ip",
            "value":  ip,
            "source": "ipinfo",
            "properties": map[string]interface{}{},
        },
    }

    var relationships []map[string]interface{}
    var wg sync.WaitGroup
    var mu sync.Mutex

    // Geolocation lookup
    wg.Add(1)
    go func() {
        defer wg.Done()
        
        // Use ip-api.com for geolocation (free, no API key)
        urlStr := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,region,city,lat,lon,isp,org,as,mobile,proxy,hosting", ip)
        
        resp, err := c.doRequest(ctx, "GET", urlStr, nil, nil)
        if err != nil {
            return
        }
        defer resp.Body.Close()

        var geoData struct {
            Status      string  `json:"status"`
            Country     string  `json:"country"`
            CountryCode string  `json:"countryCode"`
            Region      string  `json:"region"`
            City        string  `json:"city"`
            Lat         float64 `json:"lat"`
            Lon         float64 `json:"lon"`
            ISP         string  `json:"isp"`
            Org         string  `json:"org"`
            As          string  `json:"as"`
            Mobile      bool    `json:"mobile"`
            Proxy       bool    `json:"proxy"`
            Hosting     bool    `json:"hosting"`
        }

        if err := json.NewDecoder(resp.Body).Decode(&geoData); err == nil && geoData.Status == "success" {
            mu.Lock()
            entities[0]["properties"] = map[string]interface{}{
                "country":      geoData.Country,
                "country_code": geoData.CountryCode,
                "region":       geoData.Region,
                "city":         geoData.City,
                "latitude":     geoData.Lat,
                "longitude":    geoData.Lon,
                "isp":          geoData.ISP,
                "organization": geoData.Org,
                "asn":          geoData.As,
                "mobile":       geoData.Mobile,
                "proxy":        geoData.Proxy,
                "hosting":      geoData.Hosting,
            }
            mu.Unlock()

            // Create ASN entity
            if geoData.As != "" {
                asnHash := md5.Sum([]byte(fmt.Sprintf("asn:%s", geoData.As)))
                asnID := fmt.Sprintf("%x", asnHash[:])

                mu.Lock()
                entities = append(entities, map[string]interface{}{
                    "type":   "asn",
                    "value":  geoData.As,
                    "source": "ipinfo",
                    "properties": map[string]interface{}{
                        "name": geoData.Org,
                    },
                })
                relationships = append(relationships, map[string]interface{}{
                    "from_id":      ipID,
                    "to_id":        asnID,
                    "relationship": "belongs_to_asn",
                    "properties": map[string]interface{}{
                        "source": "ipinfo",
                    },
                })
                mu.Unlock()
            }
        }
    }()

    // Reverse DNS
    wg.Add(1)
    go func() {
        defer wg.Done()
        
        ptr, err := net.LookupAddr(ip)
        if err == nil && len(ptr) > 0 {
            mu.Lock()
            defer mu.Unlock()
            
            for _, hostname := range ptr {
                hostname = strings.TrimSuffix(hostname, ".")
                
                hostHash := md5.Sum([]byte(fmt.Sprintf("hostname:%s", hostname)))
                hostID := fmt.Sprintf("%x", hostHash[:])

                entities = append(entities, map[string]interface{}{
                    "type":   "hostname",
                    "value":  hostname,
                    "source": "dns",
                    "properties": map[string]interface{}{
                        "ip": ip,
                    },
                })

                relationships = append(relationships, map[string]interface{}{
                    "from_id":      hostID,
                    "to_id":        ipID,
                    "relationship": "resolves_to",
                    "properties": map[string]interface{}{
                        "source": "dns",
                    },
                })
            }
        }
    }()

    wg.Wait()

    duration := time.Since(startTime)

    return &TransformResult{
        Success:       true,
        Count:         len(entities),
        Entities:      entities,
        Relationships: relationships,
        Duration:      duration,
        Timestamp:     time.Now(),
    }, nil
}

// ========== TRANSFORM ENGINE ==========

type TransformFunc func(ctx context.Context, input string) (*TransformResult, error)

type TransformEngine struct {
    db       *ZenegoDB
    config   *Config
    clients  *APIClients
    mu       sync.RWMutex
    registry map[string]TransformFunc
    cache    map[string]*TransformResult
    cacheMu  sync.RWMutex
}

func NewTransformEngine(db *ZenegoDB, config *Config) *TransformEngine {
    engine := &TransformEngine{
        db:       db,
        config:   config,
        clients:  NewAPIClients(config),
        registry: make(map[string]TransformFunc),
        cache:    make(map[string]*TransformResult),
    }

    // Register transforms
    engine.Register("shodan", engine.shodanTransform)
    engine.Register("dns", engine.dnsTransform)
    engine.Register("whois", engine.whoisTransform)
    engine.Register("ipinfo", engine.ipinfoTransform)
    engine.Register("expand", engine.expandTransform)

    return engine
}

func (e *TransformEngine) Register(name string, fn TransformFunc) {
    e.mu.Lock()
    defer e.mu.Unlock()
    e.registry[name] = fn
}

func (e *TransformEngine) Get(name string) (TransformFunc, bool) {
    e.mu.RLock()
    defer e.mu.RUnlock()
    fn, ok := e.registry[name]
    return fn, ok
}

func (e *TransformEngine) Execute(ctx context.Context, name, input string) (*TransformResult, error) {
    // Check cache first
    if e.config.EnableCache {
        cacheKey := fmt.Sprintf("%s:%s", name, input)
        e.cacheMu.RLock()
        if cached, ok := e.cache[cacheKey]; ok {
            e.cacheMu.RUnlock()
            return cached, nil
        }
        e.cacheMu.RUnlock()
    }

    // Get transform function
    fn, ok := e.Get(name)
    if !ok {
        return nil, fmt.Errorf("transform '%s' not found", name)
    }

    // Execute transform
    result, err := fn(ctx, input)
    if err != nil {
        return nil, err
    }

    // Save to database if successful
    if result.Success {
        // Save entities
        if len(result.Entities) > 0 {
            ids, err := e.db.SaveEntityBatch(ctx, result.Entities)
            if err != nil {
                log.Printf("Warning: failed to save entities: %v", err)
            } else {
                // Update entities with IDs
                for i, id := range ids {
                    if i < len(result.Entities) {
                        result.Entities[i]["id"] = id
                    }
                }
            }
        }

        // Save relationships
        if len(result.Relationships) > 0 {
            if err := e.db.SaveRelationshipBatch(ctx, result.Relationships); err != nil {
                log.Printf("Warning: failed to save relationships: %v", err)
            }
        }

        // Cache result
        if e.config.EnableCache {
            cacheKey := fmt.Sprintf("%s:%s", name, input)
            e.cacheMu.Lock()
            e.cache[cacheKey] = result
            e.cacheMu.Unlock()
            
            // Set cache in DB
            go e.db.SetCache(ctx, cacheKey, result, e.config.CacheTTL)
        }
    }

    return result, nil
}

func (e *TransformEngine) ExecuteBatch(ctx context.Context, transforms map[string]string) (map[string]*TransformResult, error) {
    results := make(map[string]*TransformResult)
    var mu sync.Mutex
    var wg sync.WaitGroup

    for name, input := range transforms {
        wg.Add(1)
        go func(transformName, transformInput string) {
            defer wg.Done()

            result, err := e.Execute(ctx, transformName, transformInput)
            mu.Lock()
            if err != nil {
                results[transformName] = &TransformResult{
                    Success: false,
                    Error:   err.Error(),
                }
            } else {
                results[transformName] = result
            }
            mu.Unlock()
        }(name, input)
    }

    wg.Wait()
    return results, nil
}

func (e *TransformEngine) shodanTransform(ctx context.Context, input string) (*TransformResult, error) {
    return e.clients.ShodanSearch(ctx, input)
}

func (e *TransformEngine) dnsTransform(ctx context.Context, input string) (*TransformResult, error) {
    // Detect if input is IP or domain
    if net.ParseIP(input) != nil {
        return e.clients.IPInfoLookup(ctx, input)
    }
    return e.clients.DNSLookup(ctx, input)
}

func (e *TransformEngine) whoisTransform(ctx context.Context, input string) (*TransformResult, error) {
    return e.clients.WHOISLookup(ctx, input)
}

func (e *TransformEngine) ipinfoTransform(ctx context.Context, input string) (*TransformResult, error) {
    return e.clients.IPInfoLookup(ctx, input)
}

func (e *TransformEngine) expandTransform(ctx context.Context, input string) (*TransformResult, error) {
    startTime := time.Now()

    // Search for entities
    entities, _, err := e.db.Search(ctx, input, "", 100, 0)
    if err != nil {
        return nil, err
    }

    var resultEntities []map[string]interface{}
    var resultRelationships []map[string]interface{}

    for _, entity := range entities {
        // Add entity
        resultEntities = append(resultEntities, map[string]interface{}{
            "id":         entity.ID,
            "type":       entity.Type,
            "value":      entity.Value,
            "source":     entity.Source,
            "properties": entity.Properties,
            "created_at": entity.CreatedAt,
        })

        // Get relationships
        rels, err := e.db.GetRelationships(ctx, entity.ID, "both")
        if err == nil {
            for _, rel := range rels {
                resultRelationships = append(resultRelationships, map[string]interface{}{
                    "id":           rel.ID,
                    "from_id":      rel.FromID,
                    "to_id":        rel.ToID,
                    "relationship": rel.Relationship,
                    "properties":   rel.Properties,
                    "created_at":   rel.CreatedAt,
                })
            }
        }
    }

    duration := time.Since(startTime)

    return &TransformResult{
        Success:       true,
        Count:         len(resultEntities),
        Entities:      resultEntities,
        Relationships: resultRelationships,
        Duration:      duration,
        Timestamp:     time.Now(),
    }, nil
}

// ========== EXPORTERS ==========

type GraphMLKey struct {
    ID       string `xml:"id,attr"`
    For      string `xml:"for,attr"`
    Name     string `xml:"attr.name,attr"`
    Type     string `xml:"attr.type,attr"`
}

type GraphMLNode struct {
    ID    string        `xml:"id,attr"`
    Datas []GraphMLData `xml:"data"`
}

type GraphMLEdge struct {
    ID     string        `xml:"id,attr"`
    Source string        `xml:"source,attr"`
    Target string        `xml:"target,attr"`
    Datas  []GraphMLData `xml:"data"`
}

type GraphMLData struct {
    Key   string `xml:"key,attr"`
    Value string `xml:",chardata"`
}

type GraphML struct {
    XMLName xml.Name      `xml:"graphml"`
    XMLNS   string        `xml:"xmlns,attr"`
    Keys    []GraphMLKey  `xml:"key"`
    Graph   struct {
        ID          string        `xml:"id,attr"`
        EdgeDefault string        `xml:"edgedefault,attr"`
        Nodes       []GraphMLNode `xml:"node"`
        Edges       []GraphMLEdge `xml:"edge"`
    } `xml:"graph"`
}

type Exporter struct {
    mu sync.Mutex
}

func NewExporter() *Exporter {
    return &Exporter{}
}

func (e *Exporter) ToJSON(data interface{}, filename string, pretty bool) (string, error) {
    e.mu.Lock()
    defer e.mu.Unlock()

    var jsonData []byte
    var err error

    if pretty {
        jsonData, err = json.MarshalIndent(data, "", "  ")
    } else {
        jsonData, err = json.Marshal(data)
    }

    if err != nil {
        return "", err
    }

    if filename != "" {
        if err := os.WriteFile(filename, jsonData, 0644); err != nil {
            return "", err
        }
        return fmt.Sprintf("Exported to %s (%d bytes)", filename, len(jsonData)), nil
    }

    return string(jsonData), nil
}

func (e *Exporter) ToCSV(graph *GraphData, filename string) (string, error) {
    e.mu.Lock()
    defer e.mu.Unlock()

    var sb strings.Builder
    
    // Write entities
    sb.WriteString("# ENTITIES\n")
    sb.WriteString("id,type,value,source,properties,created_at\n")
    
    for _, entity := range graph.Entities {
        propsJSON, _ := json.Marshal(entity.Properties)
        propsStr := strings.ReplaceAll(string(propsJSON), ",", ";")
        propsStr = strings.ReplaceAll(propsStr, "\n", " ")
        
        line := fmt.Sprintf("\"%s\",%s,\"%s\",%s,\"%s\",%s\n",
            entity.ID,
            entity.Type,
            strings.ReplaceAll(entity.Value, "\"", "\"\""),
            entity.Source,
            propsStr,
            entity.CreatedAt.Format(time.RFC3339))
        sb.WriteString(line)
    }

    // Write relationships
    sb.WriteString("\n# RELATIONSHIPS\n")
    sb.WriteString("id,from_id,to_id,relationship,properties,created_at\n")
    
    for _, rel := range graph.Relationships {
        propsJSON, _ := json.Marshal(rel.Properties)
        propsStr := strings.ReplaceAll(string(propsJSON), ",", ";")
        
        line := fmt.Sprintf("%d,\"%s\",\"%s\",%s,\"%s\",%s\n",
            rel.ID,
            rel.FromID,
            rel.ToID,
            rel.Relationship,
            propsStr,
            rel.CreatedAt.Format(time.RFC3339))
        sb.WriteString(line)
    }

    if filename != "" {
        if err := os.WriteFile(filename, []byte(sb.String()), 0644); err != nil {
            return "", err
        }
        return fmt.Sprintf("Exported to %s (%d bytes)", filename, sb.Len()), nil
    }

    return sb.String(), nil
}

func (e *Exporter) ToGraphML(graph *GraphData, filename string) (string, error) {
    e.mu.Lock()
    defer e.mu.Unlock()

    graphml := GraphML{
        XMLNS: "http://graphml.graphdrawing.org/xmlns",
        Keys: []GraphMLKey{
            {ID: "type", For: "node", Name: "type", Type: "string"},
            {ID: "value", For: "node", Name: "value", Type: "string"},
            {ID: "source", For: "node", Name: "source", Type: "string"},
            {ID: "created", For: "node", Name: "created_at", Type: "string"},
            {ID: "rel_type", For: "edge", Name: "relationship", Type: "string"},
        },
    }

    graphml.Graph.ID = "G"
    graphml.Graph.EdgeDefault = "directed"

    // Add nodes
    nodeMap := make(map[string]string)
    for i, entity := range graph.Entities {
        nodeID := fmt.Sprintf("n%d", i)
        nodeMap[entity.ID] = nodeID

        node := GraphMLNode{
            ID: nodeID,
            Datas: []GraphMLData{
                {Key: "type", Value: entity.Type},
                {Key: "value", Value: entity.Value},
                {Key: "source", Value: entity.Source},
                {Key: "created", Value: entity.CreatedAt.Format(time.RFC3339)},
            },
        }
        graphml.Graph.Nodes = append(graphml.Graph.Nodes, node)
    }

    // Add edges
    for i, rel := range graph.Relationships {
        fromID, ok1 := nodeMap[rel.FromID]
        toID, ok2 := nodeMap[rel.ToID]

        if ok1 && ok2 {
            edge := GraphMLEdge{
                ID:     fmt.Sprintf("e%d", i),
                Source: fromID,
                Target: toID,
                Datas: []GraphMLData{
                    {Key: "rel_type", Value: rel.Relationship},
                },
            }
            graphml.Graph.Edges = append(graphml.Graph.Edges, edge)
        }
    }

    output, err := xml.MarshalIndent(graphml, "", "  ")
    if err != nil {
        return "", err
    }

    // Add XML header
    output = []byte(xml.Header + string(output))

    if filename != "" {
        if err := os.WriteFile(filename, output, 0644); err != nil {
            return "", err
        }
        return fmt.Sprintf("Exported to %s (%d bytes)", filename, len(output)), nil
    }

    return string(output), nil
}

func (e *Exporter) ToDOT(graph *GraphData, filename string) (string, error) {
    e.mu.Lock()
    defer e.mu.Unlock()

    var sb strings.Builder
    sb.WriteString("digraph Zenego {\n")
    sb.WriteString("  rankdir=LR;\n")
    sb.WriteString("  node [shape=box, style=filled, fillcolor=lightblue];\n\n")

    // Add nodes
    for _, entity := range graph.Entities {
        label := fmt.Sprintf("%s\\n%s", entity.Type, entity.Value)
        if len(label) > 50 {
            label = label[:47] + "..."
        }
        
        shape := "box"
        switch entity.Type {
        case "ip":
            shape = "ellipse"
        case "port":
            shape = "diamond"
        case "vulnerability":
            shape = "triangle"
        case "asn":
            shape = "octagon"
        }
        
        sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\", shape=%s];\n",
            entity.ID, label, shape))
    }

    // Add edges
    if len(graph.Relationships) > 0 {
        sb.WriteString("\n")
        for _, rel := range graph.Relationships {
            sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"%s\"];\n",
                rel.FromID, rel.ToID, rel.Relationship))
        }
    }

    sb.WriteString("}\n")

    if filename != "" {
        if err := os.WriteFile(filename, []byte(sb.String()), 0644); err != nil {
            return "", err
        }
        return fmt.Sprintf("Exported to %s (%d bytes)", filename, sb.Len()), nil
    }

    return sb.String(), nil
}

// ========== COMMAND LINE INTERFACE ==========

type ZenegoCLI struct {
    config   *Config
    db       *ZenegoDB
    engine   *TransformEngine
    exporter *Exporter
    reader   *bufio.Reader
    writer   *bufio.Writer
    history  []string
}

func NewZenegoCLI() (*ZenegoCLI, error) {
    // Load config
    config := DefaultConfig()
    if err := loadConfig("config.yaml", config); err != nil && !os.IsNotExist(err) {
        log.Printf("Warning: failed to load config: %v", err)
    }

    // Load .env file
    if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
        log.Printf("Warning: failed to load .env: %v", err)
    }

    // Override with environment variables
    if key := os.Getenv("SHODAN_API_KEY"); key != "" {
        config.ShodanAPIKey = key
    }
    if key := os.Getenv("VIRUSTOTAL_API_KEY"); key != "" {
        config.VirusTotalAPIKey = key
    }
    if key := os.Getenv("HIBP_API_KEY"); key != "" {
        config.HIBPAPIKey = key
    }
    if workers := os.Getenv("MAX_WORKERS"); workers != "" {
        fmt.Sscanf(workers, "%d", &config.MaxWorkers)
    }

    // Initialize database
    db, err := NewZenegoDB(config)
    if err != nil {
        return nil, fmt.Errorf("failed to initialize database: %w", err)
    }

    return &ZenegoCLI{
        config:   config,
        db:       db,
        engine:   NewTransformEngine(db, config),
        exporter: NewExporter(),
        reader:   bufio.NewReader(os.Stdin),
        writer:   bufio.NewWriter(os.Stdout),
        history:  make([]string, 0),
    }, nil
}

func loadConfig(path string, config *Config) error {
    data, err := os.ReadFile(path)
    if err != nil {
        return err
    }
    return yaml.Unmarshal(data, config)
}

func (c *ZenegoCLI) saveConfig() error {
    data, err := yaml.Marshal(c.config)
    if err != nil {
        return err
    }
    return os.WriteFile("config.yaml", data, 0644)
}

func (c *ZenegoCLI) printBanner() {
    banner := color.CyanString(`
╔════════════════════════════════════════════╗
║          ZMaltego - Ultimate OSINT        ║
║     High-Performance Graph Intelligence   ║
║             Made by @GolDer409            ║
╚════════════════════════════════════════════╝
`)
    fmt.Println(banner)
    fmt.Printf("Database: %s | Workers: %d | Cache: %v\n",
        c.config.DBPath, c.config.MaxWorkers, c.config.EnableCache)
    fmt.Println(strings.Repeat("─", 50))
}

func (c *ZenegoCLI) printPrompt() {
    fmt.Print(color.GreenString("\nZMaltego> "))
}

func (c *ZenegoCLI) readLine() (string, error) {
    line, err := c.reader.ReadString('\n')
    if err != nil {
        return "", err
    }
    line = strings.TrimSpace(line)
    if line != "" {
        c.history = append(c.history, line)
        if len(c.history) > 100 {
            c.history = c.history[1:]
        }
    }
    return line, nil
}

func (c *ZenegoCLI) runTransform(ctx context.Context, name, value string) error {
    fmt.Printf("\n%s Running %s transform on: %s\n",
        color.YellowString("→"), color.CyanString(name), color.WhiteString(value))

    // Create progress context
    progressCtx, cancel := context.WithTimeout(ctx, c.config.RequestTimeout*2)
    defer cancel()

    // Create progress spinner
    done := make(chan bool)
    go func() {
        spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
        i := 0
        for {
            select {
            case <-done:
                fmt.Print("\r\033[K")
                return
            default:
                fmt.Printf("\r%s Processing... ", color.CyanString(spinner[i%len(spinner)]))
                i++
                time.Sleep(100 * time.Millisecond)
            }
        }
    }()

    // Run transform
    start := time.Now()
    result, err := c.engine.Execute(progressCtx, name, value)
    duration := time.Since(start)

    // Stop spinner
    close(done)

    if err != nil {
        fmt.Printf("\r%s Error: %v\n", color.RedString("✗"), err)
        return err
    }

    if result.Success {
        fmt.Printf("\r%s Success! Found %d entities and %d relationships (took %v)\n",
            color.GreenString("✓"),
            result.Count,
            len(result.Relationships),
            duration.Round(time.Millisecond))

        // Show entities
        if len(result.Entities) > 0 {
            fmt.Println(color.CyanString("\nEntities:"))
            for i, entity := range result.Entities {
                if i >= 10 {
                    fmt.Printf("  ... and %d more\n", len(result.Entities)-10)
                    break
                }
                
                entityType, _ := entity["type"].(string)
                entityValue, _ := entity["value"].(string)
                entitySource, _ := entity["source"].(string)
                
                fmt.Printf("  • [%s] %s %s\n",
                    color.YellowString(entityType),
                    color.WhiteString(entityValue),
                    color.HiBlackString("("+entitySource+")"))
            }
        }

        // Show relationships
        if len(result.Relationships) > 0 {
            fmt.Println(color.CyanString("\nRelationships:"))
            for i, rel := range result.Relationships {
                if i >= 5 {
                    fmt.Printf("  ... and %d more\n", len(result.Relationships)-5)
                    break
                }
                
                fromID, _ := rel["from_id"].(string)
                toID, _ := rel["to_id"].(string)
                relType, _ := rel["relationship"].(string)
                
                fmt.Printf("  • %s -> %s [%s]\n",
                    color.WhiteString(fromID[:8]),
                    color.WhiteString(toID[:8]),
                    color.YellowString(relType))
            }
        }
    }

    return nil
}

func (c *ZenegoCLI) interactiveMode(ctx context.Context) error {
    c.printBanner()

    // Handle Ctrl+C gracefully
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigChan
        fmt.Println(color.YellowString("\n\nShutting down gracefully..."))
        c.cleanup()
        os.Exit(0)
    }()

    // Auto-save history
    go func() {
        ticker := time.NewTicker(5 * time.Minute)
        defer ticker.Stop()
        
        for {
            select {
            case <-ticker.C:
                c.saveHistory()
            case <-ctx.Done():
                return
            }
        }
    }()

    for {
        c.printPrompt()
        input, err := c.readLine()
        if err != nil {
            if err == io.EOF {
                break
            }
            log.Printf("Error reading input: %v", err)
            continue
        }

        if input == "" {
            continue
        }

        args := strings.Fields(input)
        cmd := strings.ToLower(args[0])

        switch cmd {
        case "exit", "quit", "q":
            fmt.Println(color.YellowString("\nGoodbye! 👋"))
            c.cleanup()
            return nil

        case "help", "h", "?":
            c.showHelp()

        case "transform", "t":
            if len(args) < 3 {
                fmt.Println(color.RedString("Usage: transform <name> <value>"))
                fmt.Println("Transforms: shodan, dns, whois, ipinfo, expand")
                continue
            }
            if err := c.runTransform(ctx, args[1], strings.Join(args[2:], " ")); err != nil {
                log.Printf("Transform failed: %v", err)
            }

        case "search", "s":
            if len(args) < 2 {
                fmt.Println(color.RedString("Usage: search <query> [type] [limit] [offset]"))
                continue
            }
            
            query := args[1]
            entityType := ""
            limit := 50
            offset := 0

            if len(args) > 2 {
                entityType = args[2]
            }
            if len(args) > 3 {
                fmt.Sscanf(args[3], "%d", &limit)
            }
            if len(args) > 4 {
                fmt.Sscanf(args[4], "%d", &offset)
            }

            entities, total, err := c.db.Search(ctx, query, entityType, limit, offset)
            if err != nil {
                fmt.Printf("%s Error: %v\n", color.RedString("✗"), err)
                continue
            }

            fmt.Printf("\nFound %d of %d results:\n", len(entities), total)
            for i, e := range entities {
                fmt.Printf("  %d. [%s] %s (%s) - %s\n",
                    offset+i+1,
                    color.CyanString(e.Type),
                    color.WhiteString(e.Value),
                    color.YellowString(e.Source),
                    color.HiBlackString(e.CreatedAt.Format("2006-01-02 15:04")))
            }

            if offset+limit < total {
                fmt.Printf("\nType 'search %s %s %d %d' for next page\n",
                    query, entityType, limit, offset+limit)
            }

        case "get", "g":
            if len(args) < 2 {
                fmt.Println(color.RedString("Usage: get <id>"))
                continue
            }

            entity, err := c.db.GetEntity(ctx, args[1])
            if err != nil {
                fmt.Printf("%s Error: %v\n", color.RedString("✗"), err)
                continue
            }

            fmt.Printf("\nEntity: [%s] %s\n", color.CyanString(entity.Type), color.WhiteString(entity.Value))
            fmt.Printf("  ID:     %s\n", entity.ID)
            fmt.Printf("  Source: %s\n", entity.Source)
            fmt.Printf("  Created: %s\n", entity.CreatedAt.Format(time.RFC3339))
            
            if len(entity.Properties) > 0 {
                fmt.Println("  Properties:")
                propsJSON, _ := json.MarshalIndent(entity.Properties, "    ", "  ")
                fmt.Printf("    %s\n", string(propsJSON))
            }

            // Get relationships
            rels, err := c.db.GetRelationships(ctx, entity.ID, "both")
            if err == nil && len(rels) > 0 {
                fmt.Println("  Relationships:")
                for _, rel := range rels {
                    direction := "→"
                    targetID := rel.ToID
                    if rel.ToID == entity.ID {
                        direction = "←"
                        targetID = rel.FromID
                    }
                    fmt.Printf("    %s %s [%s]\n",
                        direction,
                        color.WhiteString(targetID[:8]),
                        color.YellowString(rel.Relationship))
                }
            }

        case "graph", "gr":
            startID := ""
            depth := 2
            limit := 100

            if len(args) > 1 {
                // Search for entity first
                entities, _, err := c.db.Search(ctx, args[1], "", 1, 0)
                if err == nil && len(entities) > 0 {
                    startID = entities[0].ID
                } else {
                    startID = args[1]
                }
            }
            if len(args) > 2 {
                fmt.Sscanf(args[2], "%d", &depth)
            }
            if len(args) > 3 {
                fmt.Sscanf(args[3], "%d", &limit)
            }

            graph, err := c.db.GetGraph(ctx, startID, depth, limit)
            if err != nil {
                fmt.Printf("%s Error: %v\n", color.RedString("✗"), err)
                continue
            }

            fmt.Printf("\nGraph contains:\n")
            fmt.Printf("  • %d entities\n", color.CyanString("%d", len(graph.Entities)))
            fmt.Printf("  • %d relationships\n", color.CyanString("%d", len(graph.Relationships)))

            if len(graph.Entities) > 0 {
                fmt.Println(color.CyanString("\nEntities:"))
                for i, e := range graph.Entities {
                    if i >= 10 {
                        fmt.Printf("  ... and %d more\n", len(graph.Entities)-10)
                        break
                    }
                    fmt.Printf("  %d. [%s] %s\n",
                        i+1,
                        color.YellowString(e.Type),
                        color.WhiteString(e.Value))
                }
            }

        case "export", "e":
            if len(args) < 2 {
                fmt.Println(color.RedString("Usage: export <format> [filename] [start_id] [depth]"))
                fmt.Println("Formats: json, csv, graphml, dot")
                continue
            }

            format := strings.ToLower(args[1])
            filename := ""
            startID := ""
            depth := 2

            if len(args) > 2 {
                filename = args[2]
            } else {
                filename = fmt.Sprintf("zenego_export_%d.%s",
                    time.Now().Unix(), format)
            }
            if len(args) > 3 {
                startID = args[3]
            }
            if len(args) > 4 {
                fmt.Sscanf(args[4], "%d", &depth)
            }

            graph, err := c.db.GetGraph(ctx, startID, depth, 1000)
            if err != nil {
                fmt.Printf("%s Error: %v\n", color.RedString("✗"), err)
                continue
            }

            var result string
            switch format {
            case "json":
                result, err = c.exporter.ToJSON(graph, filename, true)
            case "csv":
                result, err = c.exporter.ToCSV(graph, filename)
            case "graphml":
                result, err = c.exporter.ToGraphML(graph, filename)
            case "dot":
                result, err = c.exporter.ToDOT(graph, filename)
            default:
                fmt.Println(color.RedString("Unknown format. Use: json, csv, graphml, dot"))
                continue
            }

            if err != nil {
                fmt.Printf("%s Error: %v\n", color.RedString("✗"), err)
                continue
            }

            fmt.Printf("%s %s\n", color.GreenString("✓"), result)

        case "stats", "st":
            stats, err := c.db.GetStats(ctx)
            if err != nil {
                fmt.Printf("%s Error: %v\n", color.RedString("✗"), err)
                continue
            }

            fmt.Println(color.CyanString("\nDatabase Statistics:"))
            fmt.Printf("  Total Entities:      %d\n", stats["total_entities"])
            fmt.Printf("  Total Relationships: %d\n", stats["total_relationships"])
            fmt.Printf("  Total Jobs:          %d\n", stats["total_jobs"])
            fmt.Printf("  Database Size:       %d bytes\n", stats["database_size"])

            if entitiesByType, ok := stats["entities_by_type"].(map[string]int); ok {
                fmt.Println(color.CyanString("\nEntities by Type:"))
                for typ, count := range entitiesByType {
                    fmt.Printf("  %s: %d\n", typ, count)
                }
            }

            if entitiesBySource, ok := stats["entities_by_source"].(map[string]int); ok {
                fmt.Println(color.CyanString("\nEntities by Source:"))
                for source, count := range entitiesBySource {
                    fmt.Printf("  %s: %d\n", source, count)
                }
            }

        case "config", "c":
            c.showConfig()

        case "set":
            if len(args) < 3 {
                fmt.Println(color.RedString("Usage: set <key> <value>"))
                fmt.Println("Keys: shodan_api_key, virustotal_api_key, hibp_api_key, max_workers, cache_ttl, request_timeout, rate_limit")
                continue
            }

            key := args[1]
            value := args[2]

            switch key {
            case "shodan_api_key":
                c.config.ShodanAPIKey = value
            case "virustotal_api_key":
                c.config.VirusTotalAPIKey = value
            case "hibp_api_key":
                c.config.HIBPAPIKey = value
            case "max_workers":
                fmt.Sscanf(value, "%d", &c.config.MaxWorkers)
            case "cache_ttl":
                ttl, _ := time.ParseDuration(value)
                c.config.CacheTTL = ttl
            case "request_timeout":
                timeout, _ := time.ParseDuration(value)
                c.config.RequestTimeout = timeout
            case "rate_limit":
                fmt.Sscanf(value, "%d", &c.config.RateLimit)
            default:
                fmt.Println(color.RedString("Unknown config key"))
                continue
            }

            if err := c.saveConfig(); err != nil {
                fmt.Printf("%s Failed to save config: %v\n", color.RedString("✗"), err)
            } else {
                fmt.Printf("%s Config updated\n", color.GreenString("✓"))
            }

        case "clear":
            if len(args) > 1 && args[1] == "--force" {
                confirm := c.promptConfirm("Are you sure you want to clear the database?")
                if confirm {
                    if err := c.clearDatabase(ctx); err != nil {
                        fmt.Printf("%s Error: %v\n", color.RedString("✗"), err)
                    } else {
                        fmt.Printf("%s Database cleared\n", color.GreenString("✓"))
                    }
                }
            } else {
                fmt.Println(color.YellowString("Use 'clear --force' to clear database"))
            }

        case "history", "hist":
            for i, cmd := range c.history {
                fmt.Printf("%4d  %s\n", i+1, cmd)
            }

        default:
            fmt.Printf("Unknown command: %s\n", color.RedString(cmd))
            fmt.Println("Type 'help' for available commands")
        }
    }

    return nil
}

func (c *ZenegoCLI) promptConfirm(message string) bool {
    fmt.Printf("%s [y/N]: ", message)
    response, err := c.readLine()
    if err != nil {
        return false
    }
    response = strings.ToLower(response)
    return response == "y" || response == "yes"
}

func (c *ZenegoCLI) showHelp() {
    help := color.CyanString(`
╔════════════════════════════════════════════════════════════╗
║                          COMMANDS                         ║
╠════════════════════════════════════════════════════════════╣
║       transform  <name> <value>   Run a transform          ║
║      Transforms: shodan, dns, whois, ipinfo, expand        ║
║                                                            ║
║ search     <query> [type]  Search database                 ║
║ get        <id>            Get entity details              ║
║ graph      [id] [depth]    View graph                      ║
║ export     <fmt> [file]    Export data (json/csv/graphml)  ║
║ stats                      Show database statistics        ║
║ config                     Show configuration              ║
║ set        <key> <value>   Set configuration               ║
║ clear      --force         Clear database                  ║
║ history                    Show command history            ║
║ exit, quit                 Exit program                    ║
║ help, h                    Show this help                  ║
╚════════════════════════════════════════════════════════════╝

Examples:
  transform shodan 8.8.8.8
  transform dns example.com
  search google
  graph 8.8.8.8 3
  export json mygraph.json
`)
    fmt.Print(help)
}

func (c *ZenegoCLI) showConfig() {
    fmt.Printf("\n%s\n", color.CyanString("Current Configuration:"))
    fmt.Printf("  Shodan API Key:     %s\n", maskKey(c.config.ShodanAPIKey))
    fmt.Printf("  VirusTotal API Key: %s\n", maskKey(c.config.VirusTotalAPIKey))
    fmt.Printf("  HIBP API Key:       %s\n", maskKey(c.config.HIBPAPIKey))
    fmt.Printf("  Max Workers:        %d\n", c.config.MaxWorkers)
    fmt.Printf("  Cache TTL:          %v\n", c.config.CacheTTL)
    fmt.Printf("  Request Timeout:    %v\n", c.config.RequestTimeout)
    fmt.Printf("  Rate Limit:         %d req/s\n", c.config.RateLimit)
    fmt.Printf("  Enable Cache:       %v\n", c.config.EnableCache)
    fmt.Printf("  Database Path:      %s\n", c.config.DBPath)
    fmt.Printf("  User Agent:         %s\n", c.config.UserAgent)
    fmt.Println()
}

func (c *ZenegoCLI) clearDatabase(ctx context.Context) error {
    tx, err := c.db.db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    tables := []string{"relationships", "entities", "cache", "jobs"}
    for _, table := range tables {
        if _, err := tx.Exec(fmt.Sprintf("DELETE FROM %s", table)); err != nil {
            return err
        }
    }

    return tx.Commit()
}

func (c *ZenegoCLI) saveHistory() {
    if len(c.history) == 0 {
        return
    }

    data := strings.Join(c.history, "\n")
    os.WriteFile(".zenego_history", []byte(data), 0644)
}

func (c *ZenegoCLI) loadHistory() {
    data, err := os.ReadFile(".zenego_history")
    if err != nil {
        return
    }
    c.history = strings.Split(strings.TrimSpace(string(data)), "\n")
}

func (c *ZenegoCLI) cleanup() {
    c.saveHistory()
    c.db.Close()
    c.writer.Flush()
}

func maskKey(key string) string {
    if len(key) <= 8 {
        return "****"
    }
    return key[:4] + "****" + key[len(key)-4:]
}

// ========== MAIN ==========

func main() {
    // Set up logging
    log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
    log.SetOutput(os.Stderr)

    // Parse command line arguments
    if len(os.Args) > 1 {
        if err := runCommand(os.Args[1:]); err != nil {
            log.Fatal(err)
        }
        return
    }

    // Run interactive mode
    cli, err := NewZenegoCLI()
    if err != nil {
        log.Fatalf("Failed to initialize Zenego: %v", err)
    }
    defer cli.cleanup()

    // Load history
    cli.loadHistory()

    ctx := context.Background()
    if err := cli.interactiveMode(ctx); err != nil {
        log.Fatalf("Error: %v", err)
    }
}

func runCommand(args []string) error {
    cli, err := NewZenegoCLI()
    if err != nil {
        return fmt.Errorf("failed to initialize: %w", err)
    }
    defer cli.cleanup()

    ctx := context.Background()

    switch args[0] {
    case "transform":
        if len(args) < 3 {
            return fmt.Errorf("usage: zenego transform <name> <value>")
        }
        return cli.runTransform(ctx, args[1], args[2])

    case "search":
        if len(args) < 2 {
            return fmt.Errorf("usage: zenego search <query> [type]")
        }
        query := args[1]
        entityType := ""
        if len(args) > 2 {
            entityType = args[2]
        }
        
        entities, total, err := cli.db.Search(ctx, query, entityType, 50, 0)
        if err != nil {
            return err
        }
        
        fmt.Printf("Found %d of %d results:\n", len(entities), total)
        for _, e := range entities {
            fmt.Printf("[%s] %s (%s)\n", e.Type, e.Value, e.Source)
        }
        return nil

    case "export":
        if len(args) < 2 {
            return fmt.Errorf("usage: zenego export <json|csv|graphml|dot> [filename]")
        }
        format := args[1]
        filename := ""
        if len(args) > 2 {
            filename = args[2]
        } else {
            filename = fmt.Sprintf("zenego_export_%d.%s", time.Now().Unix(), format)
        }

        graph, err := cli.db.GetGraph(ctx, "", 2, 1000)
        if err != nil {
            return err
        }

        var result string
        switch format {
        case "json":
            result, err = cli.exporter.ToJSON(graph, filename, true)
        case "csv":
            result, err = cli.exporter.ToCSV(graph, filename)
        case "graphml":
            result, err = cli.exporter.ToGraphML(graph, filename)
        case "dot":
            result, err = cli.exporter.ToDOT(graph, filename)
        default:
            return fmt.Errorf("unknown format: %s", format)
        }

        if err != nil {
            return err
        }
        fmt.Println(result)
        return nil

    case "stats":
        stats, err := cli.db.GetStats(ctx)
        if err != nil {
            return err
        }
        jsonData, _ := json.MarshalIndent(stats, "", "  ")
        fmt.Println(string(jsonData))
        return nil

    default:
        return fmt.Errorf("unknown command: %s", args[0])
    }
}
