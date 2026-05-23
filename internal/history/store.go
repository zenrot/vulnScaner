package history

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	maxEntries = 100
	dbName     = "vulnscanner"
	colName    = "scans"
)

type Summary struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	ArchiveName string    `json:"archive_name"`
	Provider    string    `json:"provider"`
	ShouldFail  bool      `json:"should_fail"`
	Stats       any       `json:"stats"`
}

type Record struct {
	Summary
	Report any `json:"report"`
}

type Store struct {
	col *mongo.Collection
}

type scanDoc struct {
	ID          string    `bson:"_id"`
	Timestamp   time.Time `bson:"timestamp"`
	ArchiveName string    `bson:"archive_name"`
	Provider    string    `bson:"provider"`
	ShouldFail  bool      `bson:"should_fail"`
	Stats       string    `bson:"stats"`
	Report      string    `bson:"report"`
}

func New(uri string) (*Store, error) {
	if uri == "" {
		return nil, nil
	}
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("history: connect: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("history: ping: %w", err)
	}
	col := client.Database(dbName).Collection(colName)
	_, err = col.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "timestamp", Value: -1}},
	})
	if err != nil {
		return nil, fmt.Errorf("history: create index: %w", err)
	}
	return &Store{col: col}, nil
}

func (s *Store) Save(archiveName, provider string, shouldFail bool, stats, report any) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	statsJSON, err := json.Marshal(stats)
	if err != nil {
		return "", err
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = s.col.InsertOne(ctx, scanDoc{
		ID:          id,
		Timestamp:   time.Now().UTC(),
		ArchiveName: archiveName,
		Provider:    provider,
		ShouldFail:  shouldFail,
		Stats:       string(statsJSON),
		Report:      string(reportJSON),
	})
	if err != nil {
		return "", err
	}
	go s.prune()
	return id, nil
}

func (s *Store) List() ([]Summary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetProjection(bson.D{
			{Key: "_id", Value: 1},
			{Key: "timestamp", Value: 1},
			{Key: "archive_name", Value: 1},
			{Key: "provider", Value: 1},
			{Key: "should_fail", Value: 1},
			{Key: "stats", Value: 1},
		})
	cursor, err := s.col.Find(ctx, bson.D{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var summaries []Summary
	for cursor.Next(ctx) {
		var doc scanDoc
		if err := cursor.Decode(&doc); err != nil {
			continue
		}
		summaries = append(summaries, toSummary(doc))
	}
	return summaries, cursor.Err()
}

func (s *Store) Get(id string) (*Record, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var doc scanDoc
	err := s.col.FindOne(ctx, bson.M{"_id": id}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sum := toSummary(doc)
	var report any
	_ = json.Unmarshal([]byte(doc.Report), &report)
	return &Record{Summary: sum, Report: report}, nil
}

func (s *Store) prune() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	count, err := s.col.CountDocuments(ctx, bson.D{})
	if err != nil || count <= maxEntries {
		return
	}
	cursor, err := s.col.Find(ctx, bson.D{},
		options.Find().
			SetSort(bson.D{{Key: "timestamp", Value: 1}}).
			SetLimit(count-maxEntries).
			SetProjection(bson.D{{Key: "_id", Value: 1}}),
	)
	if err != nil {
		return
	}
	defer cursor.Close(ctx)
	var ids []any
	for cursor.Next(ctx) {
		var doc struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&doc); err == nil {
			ids = append(ids, doc.ID)
		}
	}
	if len(ids) > 0 {
		_, _ = s.col.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}})
	}
}

func toSummary(doc scanDoc) Summary {
	var stats any
	_ = json.Unmarshal([]byte(doc.Stats), &stats)
	return Summary{
		ID:          doc.ID,
		Timestamp:   doc.Timestamp,
		ArchiveName: doc.ArchiveName,
		Provider:    doc.Provider,
		ShouldFail:  doc.ShouldFail,
		Stats:       stats,
	}
}

func randomID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
