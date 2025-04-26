package main

import (
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/authfully/authfully"
	authfullysimple "github.com/authfully/authfully/simple-suite"
	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Default port to use if not set in the environment variable
const defaultPort = "8081"

// Hard code to use this authentication endpoint path
const authenticationEndpointPath = "/oauth2/login"

// Hard code to use this authorization endpoint path
const authorizationEndpointPath = "/oauth2/authorize"

// Hard code to use this token endpoint path
const tokenEndpointPath = "/oauth2/token"

func requestContextMiddleware(
	env *authfully.Environment,
	h http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a new context with the environment
		ctx := authfully.WithEnvironment(r.Context(), env)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// DefaultAuthSubmissionDecoder is a default implementation of the AuthSubmissionDecoderFunc
// type and AuthSubmissionDecoder interface. It is used to decode the authentication submission
// from the request.
func DefaultAuthSubmissionDecoder(
	r *http.Request,
) authfully.AuthSubmission {
	// TODO: implement me
	return nil
}

func getLoggers(debug bool) (*slog.Logger, gormlogger.Interface) {
	var slogLevel slog.Level
	gormLogLevel := gormlogger.Silent
	slogLevel = slog.LevelInfo

	// Setup log level for the loggers
	if debug {
		slogLevel = slog.LevelDebug
		gormLogLevel = gormlogger.Info
	}

	// Create a new slog.Logger
	slogLogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slogLevel,
	}))

	// Create a new gorm logger
	gormLogger := gormlogger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		gormlogger.Config{
			SlowThreshold:             0,            // Slow SQL threshold
			LogLevel:                  gormLogLevel, // Log level
			IgnoreRecordNotFoundError: true,         // Ignore ErrRecordNotFound error for logger
			ParameterizedQueries:      true,         // Don't include params in the SQL log
			Colorful:                  true,         // Disable color
		},
	)

	return slogLogger, gormLogger
}

func main() {
	// Set up a temporary logger for the initial steps
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("starting")

	// Load if .env exists
	if _, err := os.Stat(".env"); err == nil {
		logger.Info("Loading .env file")
		err := godotenv.Load()
		if err != nil {
			logger.Error("Error loading .env file", "error", err)
			panic(err)
		}
	}

	// Check debug flag from environment variable
	debugFlag := strings.ToLower(os.Getenv("DEBUG"))
	logger, gormLogger := getLoggers(debugFlag == "true" || debugFlag == "1")

	// Parse the port number from the environment variable
	addr, err := authfullysimple.ParseAddress(os.Getenv("PORT"), defaultPort)
	if err != nil {
		logger.Error("Invalid port number", "error", err)
		panic(err)
	}

	// Initialize the database
	db, err := gorm.Open(sqlite.Open("auth-server.sqlite3"), &gorm.Config{
		Logger: gormLogger,
	})

	if err != nil {
		logger.Error("Failed to connect database", "error", err)
		panic(err)
	}
	logger.Info("connected to database")

	// Migrate the schema
	logger.Info("migrating database schema")
	cs := authfullysimple.NewClientStore(db)
	if err := cs.AutoMigrate(); err != nil {
		logger.Error("Failed to migrate client store", "error", err)
		panic(err)
	}
	us := authfullysimple.NewUserStore(db)
	if err := us.AutoMigrate(); err != nil {
		logger.Error("Failed to migrate user store", "error", err)
		panic(err)
	}
	logger.Info("Migrated database schema")

	// Create an environment
	env := &authfully.Environment{
		AuthEndpoint:                authenticationEndpointPath,
		TokenEndpoint:               tokenEndpointPath,
		UserStore:                   us,
		ClientStore:                 cs,
		TokenSessionStore:           nil, // TODO: implement me
		RandomGenerator:             authfully.NewRandomGenerator(),
		AuthorizationRequestDecoder: authfully.AuthorizationRequestDecoderFunc(authfully.DefaultAuthorizationRequestDecoder),
		AuthSubmissionDecoder:       authfully.AuthSubmissionDecoderFunc(DefaultAuthSubmissionDecoder), // TODO: implement me
		Logger:                      logger,
	}

	m := http.NewServeMux()

	m.Handle(
		authenticationEndpointPath,
		requestContextMiddleware(
			env,
			authfully.NewAuthorizationEndpointHandler(),
		),
	)

	m.HandleFunc(tokenEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Received request for token endpoint")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token": "example_token", "token_type": "bearer"}`))
		// Handle the token endpoint
	})

	// Server the default handler
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}
	defer listener.Close()
	logger.Info(fmt.Sprintf("Listening on %s", addr))
	err = http.Serve(listener, m)
	if err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
	logger.Info("Server stopped")
}
