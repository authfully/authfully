package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/authfully/authfully"
	authfullysimple "github.com/authfully/authfully/simple-suite"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	cli "github.com/urfave/cli/v2"
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

func encodeKeyToFile(key *ecdsa.PrivateKey, filePath string) error {
	// Marshal the private key to PEM format
	priKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Create a public key for the above key
	pubKey, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Encode the private key to PEM format
	f, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	err = pem.Encode(f,
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: priKey,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	// Encode the public key to PEM format
	return pem.Encode(f,
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKey,
		},
	)
}

func decodeKeyFromFile(filePath string) (*ecdsa.PrivateKey, error) {
	// Read the private key from the file
	keyData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Parse the private key
	key, err := jwt.ParseECPrivateKeyFromPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return key, nil
}

func serve(
	addr string,
	keyFilePath string,
	us authfully.UserStore,
	cs authfully.ClientStore,
	ts authfully.TokenSessionStore,
	logger *slog.Logger,
) {

	var key *ecdsa.PrivateKey

	// Check if the key file exists
	if _, err := os.Stat(keyFilePath); os.IsNotExist(err) {
		logger.Info("Key file not found, generating a new key")

		// Generate a new PEM ecdsa key file
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			logger.Error("Failed to generate private key", "error", err)
			panic(err)
		}

		// Store the key into PEM file
		err = encodeKeyToFile(key, keyFilePath)
		if err != nil {
			logger.Error("Failed to encode private key to file", "error", err)
			panic(err)
		}

		logger.Info("Private key generated and stored in file", "file", keyFilePath)
	} else {
		key, err = decodeKeyFromFile(keyFilePath)
		if err != nil {
			logger.Error("Failed to decode key from file", "error", err)
			panic(err)
		}
	}

	// Create an environment
	env := &authfully.Environment{
		AuthEndpoint:      authenticationEndpointPath,
		TokenEndpoint:     tokenEndpointPath,
		UserStore:         us,
		ClientStore:       cs,
		TokenSessionStore: ts,
		AuthSessionHandler: NewJwtCookieSessionHandler(
			func(r *http.Request) *http.Cookie {
				return &http.Cookie{
					Name:     "auth_session",
					Path:     "/",
					HttpOnly: true,
					Secure:   r.TLS != nil,
					SameSite: http.SameSiteLaxMode,
				}
			},
			key,
			jwt.SigningMethodES256, // TODO: use a better signing method
			authfully.AuthorizationRequestDecoderFunc(authfully.DefaultAuthorizationRequestDecoder),
		),
		TokenGenerator:              authfully.NewDefaultTokenGenerator(32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
		TokenSessionPolicy:          authfully.NewDefaultTokenSessionPolicy(60 * 60),
		RandomGenerator:             authfully.NewRandomGenerator(),
		AuthorizationRequestDecoder: authfully.AuthorizationRequestDecoderFunc(authfully.DefaultAuthorizationRequestDecoder),
		Logger:                      logger,
	}

	m := http.NewServeMux()

	authenticationPageTemplate, err := template.New("page.html").Parse(authfully.AuthenticationPageHTML())
	if err != nil {
		logger.Error("Failed to parse authentication page template", "error", err)
		panic(err)
	}

	scopeAuthorizationPageTemplate, err := template.New("scope.html").Parse(authfully.ScopeAuthorizationPageHTML())
	if err != nil {
		logger.Error("Failed to parse scope authorization page template", "error", err)
		panic(err)
	}

	errorPageTemplate, err := template.New("error.html").Parse(authfully.ErrorPageHTML())
	if err != nil {
		logger.Error("Failed to parse error page template", "error", err)
		panic(err)
	}

	m.Handle(
		authenticationEndpointPath,
		requestContextMiddleware(
			env,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				env := authfully.GetEnvironment(r.Context())
				if env == nil {
					panic("Environment not found")
				}

				// TODO: check if the request is a valid authorization request
				// TODO: if not, check session or cookie for the authorization request

				if r.Method == "GET" {
					// Decode the authorization submission
					ar, err := env.AuthorizationRequestDecoder.Decode(r.URL.Query())
					if err != nil {
						logger.Error("Error handling user form submission", "error", err)
						return
					}

					// Check if the client ID is valid
					client, err := env.ClientStore.GetClientByID(ar.ClientID)
					if err != nil {
						logger.Error("Error handling loading client of client_id in authorization request",
							"client_id", ar.ClientID,
							"error", err,
						)
						w.Header().Set("Content-Type", "text/html")
						w.WriteHeader(http.StatusBadRequest)
						errorPageTemplate.Execute(w, &authfully.ErrorPageFields{
							Title:            "Error",
							ErrorDescription: "Client not found",
							RedirectURI:      "", // TODO: fix me
						})
						return
					}

					// handle session / cookie for storing the ar
					env.AuthSessionHandler.SetSession(w, r, &authfully.AuthSession{
						AuthorizationRequest: ar,
						ClientID:             client.GetID(),
					})

					authenticationPageTemplate.Execute(w, authfully.UserInterfacePageFields{
						Title:      "Login",
						ButtonText: "Login",
						Action:     r.URL.Path,
					})
					return
				}

				// Handle a simple form submission
				if r.Method == "POST" {
					sess, err := env.AuthSessionHandler.GetSession(r)
					if err != nil {
						logger.Error("Error handling user form submission", "error", err)
						w.Header().Set("Content-Type", "text/html")
						w.WriteHeader(http.StatusBadRequest)
						errorPageTemplate.Execute(w, &authfully.ErrorPageFields{
							Title:            "Error",
							ErrorDescription: err.Error(),
							RedirectURI:      "", // TODO: fix me
						})
						return
					}
					if sess == nil {
						err = fmt.Errorf("session do not exists")
						logger.Error("Error handling user form submission", "error", err)
						w.Header().Set("Content-Type", "text/html")
						w.WriteHeader(http.StatusBadRequest)
						errorPageTemplate.Execute(w, &authfully.ErrorPageFields{
							Title:            "Error",
							ErrorDescription: err.Error(),
							RedirectURI:      "", // TODO: fix me
						})
						return
					}

					r.ParseForm() // Parse the form data
					email := r.Form.Get("email")
					password := r.Form.Get("password")
					//nounce := r.Form.Get("nounce")

					// Check if the user can be found in the user store
					u, err := env.UserStore.GetUserByLoginName(email)
					if err != nil {
						logger.Error("Error handling user form submission", "error", err)
						authenticationPageTemplate.Execute(w, authfully.UserInterfacePageFields{
							Title:      "Login",
							ButtonText: "Login",
							Action:     r.URL.Path,
							Form:       r.Form,
							Warning: &authfully.UserInterfaceWarning{
								Description: "User with this email not found",
								InnerError:  err,
								Form:        r.Form,
							},
						})
						return
					}

					// Check if the password matches the found user
					if err = u.CheckPassword(password); err != nil {
						logger.Error("Error handling user form submission", "error", err)
						authenticationPageTemplate.Execute(w, authfully.UserInterfacePageFields{
							Title:      "Login",
							ButtonText: "Login",
							Action:     r.URL.Path,
							Form:       r.Form,
							Warning: &authfully.UserInterfaceWarning{
								Description: "Password is not correct",
								InnerError:  err,
								Form:        r.Form,
							},
						})
						return
					}

					// Set the user ID in the session
					sess.UserID = u.GetID()
					env.AuthSessionHandler.SetSession(w, r, sess)

					// Redirect to the authorization endpoint
					w.Header().Set("Location", authorizationEndpointPath)
					w.WriteHeader(http.StatusFound)
					return
				}

				// Unsupported method error page
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusMethodNotAllowed)
				errorPageTemplate.Execute(w, &authfully.ErrorPageFields{
					Title:            "Error",
					ErrorDescription: "Unsupported method",
					RedirectURI:      "", // TODO: fix
				})
			}),
		),
	)

	// Specific authorization page endpoint to be added for scope approval
	m.Handle(
		authorizationEndpointPath,
		requestContextMiddleware(
			env,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				env := authfully.GetEnvironment(r.Context())
				if env == nil {
					panic("Environment not found")
				}

				sess, err := env.AuthSessionHandler.GetSession(r)
				if err != nil {
					logger.Error("Error handling user form submission", "error", err)
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusBadRequest)
					errorPageTemplate.Execute(w, &authfully.ErrorPageFields{
						Title:            "Error",
						ErrorDescription: err.Error(),
						RedirectURI:      "", // TODO: fix me
					})
					return
				}
				if sess == nil {
					err = fmt.Errorf("session do not exists")
					logger.Error("Error handling authorization form page view", "error", err)
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusBadRequest)
					errorPageTemplate.Execute(w, &authfully.ErrorPageFields{
						Title:            "Error",
						ErrorDescription: err.Error(),
						RedirectURI:      "", // TODO: fix me
					})
					return
				}

				if sess.AuthorizationRequest == nil {
					err = fmt.Errorf("no authorization request found in session")
					logger.Error("Error handling authorization form page view", "error", err)
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusBadRequest)
					errorPageTemplate.Execute(w, &authfully.ErrorPageFields{
						Title:            "Error",
						ErrorDescription: err.Error(),
						RedirectURI:      "", // TODO: fix me
					})
					return
				}

				// Load the client of the session
				client, err := env.ClientStore.GetClientByID(sess.AuthorizationRequest.ClientID)
				if err != nil {
					logger.Error("Error loading client for the scope authorization page",
						"client_id", sess.AuthorizationRequest.ClientID,
						"error", err,
					)
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusBadRequest)
					errorPageTemplate.Execute(w, &authfully.ErrorPageFields{
						Title:            "Error",
						ErrorDescription: err.Error(),
						RedirectURI:      "", // TODO: fix me
					})
					return
				}

				// load the user of the session
				user, err := env.UserStore.GetUserByID(sess.UserID)
				if err != nil {
					logger.Error("Error loading user for the scope authorization page",
						"user_id", sess.UserID,
						"error", err,
					)
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusBadRequest)
					errorPageTemplate.Execute(w, &authfully.ErrorPageFields{
						Title:            "Error",
						ErrorDescription: err.Error(),
						RedirectURI:      "", // TODO: fix me
					})
					return
				}

				if r.Method == "POST" {
					// TODO: add some sort of check here

					// Creaate PendingTokenSession with TokenSessionStore
					req := &authfully.TokenSessionRequest{
						GrantType:           "authorization_code",
						ClientID:            client.GetID(),
						UserID:              user.GetID(),
						Code:                env.TokenGenerator.Generate(),
						Scope:               sess.AuthorizationRequest.Scope,
						CodeChallengeMethod: sess.AuthorizationRequest.CodeChallengeMethod,
						CodeChallenge:       sess.AuthorizationRequest.CodeChallenge,
					}
					pendingSess, err := ts.CreatePendingTokenSession(req, "Bearer")
					if err != nil {
						logger.Error("Error creating pending token session", "error", err)
						w.Header().Set("Content-Type", "text/html")
						w.WriteHeader(http.StatusBadRequest)

						errorPageTemplate.Execute(w, &authfully.ErrorPageFields{
							Title:            "Error",
							ErrorDescription: err.Error(),
							RedirectURI:      "", // TODO: fix
						})
						return
					}
					logger.Info("Created pending token session", "session_id", pendingSess.GetID())

					// Redirect user back to client
					resp := &authfully.AuthResponse{
						ResponseType: sess.AuthorizationRequest.ResponseType,
						Code:         req.Code,
						State:        sess.AuthorizationRequest.State,
					}

					w.Header().Set("Location", sess.AuthorizationRequest.RedirectURIWithQuery(resp.ToQuery()))
					w.WriteHeader(http.StatusFound)
					return
				}

				scopeAuthorizationPageTemplate.Execute(w, &authfully.UserInterfacePageFields{
					Title:                "Authorization",
					ButtonText:           "Authorize",
					AuthorizationRequest: sess.AuthorizationRequest,
					Client:               client,
					User:                 user,
					Action:               r.URL.Path,
					Form:                 r.Form,
				})
			}),
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

// getDatabase initializes the database connection
func getDatabase(dsn string, gormLogger gormlogger.Interface, logger *slog.Logger) *gorm.DB {
	// Initialize the database
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormLogger,
	})
	if err != nil {
		logger.Error("Failed to connect database", "error", err)
		panic(err)
	}
	logger.Info("connected to database")
	return db
}

// initializeStores initializes the stores object and the underlying tables.
// Do automigration of the tables.
func initializeStores(db *gorm.DB, logger *slog.Logger) (authfully.UserStore, authfully.ClientStore, authfully.TokenSessionStore) {
	logger.Info("database migration started")

	// Initialize the user store
	us := authfullysimple.NewUserStore(db)
	if err := us.AutoMigrate(); err != nil {
		log.Fatalf("Failed to migrate user store: %v", err)
	}

	// Initialize the client store
	cs := authfullysimple.NewClientStore(db)
	if err := cs.AutoMigrate(); err != nil {
		log.Fatalf("Failed to migrate client store: %v", err)
	}

	ts := authfullysimple.NewTokenSessionStore(db, nil, nil)
	if err := ts.AutoMigrate(); err != nil {
		log.Fatalf("Failed to migrate token session store: %v", err)
	}

	logger.Info("database migration completed")

	return us, cs, ts
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

	(&cli.App{
		Name:  "auth-server",
		Usage: "A simple OAuth 2.0 server",
		Commands: []*cli.Command{
			{
				Name: "serve",
				Action: func(c *cli.Context) error {
					// Parse the port number from the environment variable
					addr, err := authfullysimple.ParseAddress(os.Getenv("PORT"), defaultPort)
					if err != nil {
						logger.Error("Invalid port number", "error", err)
						panic(err)
					}

					// Initialize the database
					db := getDatabase("auth-server.sqlite3", gormLogger, logger)

					// Initialize the stores
					us, cs, ts := initializeStores(db, logger)

					// Start the server
					serve(addr, "auth-server.pem", us, cs, ts, logger)
					return nil
				},
			},
			{
				Name: "migrate",
				Action: func(c *cli.Context) error {
					// Initialize the database
					db := getDatabase("auth-server.sqlite3", gormLogger, logger)

					// Initialize the stores
					initializeStores(db, logger)
					return nil
				},
			},
			{
				Name: "client",
				Subcommands: []*cli.Command{
					{
						Name: "create",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "name",
								Usage:    "Name of the client",
								Required: true,
							},
							&cli.StringSliceFlag{
								Name:     "redirect-uri",
								Usage:    "Redirect URI of the client. Can be specified multiple times.",
								Required: true,
							},
							&cli.StringSliceFlag{
								Name:     "scope",
								Usage:    "Valid scope of the client. Can be specified multiple times.",
								Required: true,
							},
						},
						Action: func(c *cli.Context) error {
							var err error

							// Initialize the database
							db := getDatabase("auth-server.sqlite3", gormLogger, logger)

							// Start transaction
							tx := db.Begin()

							// Create a new client store
							cs := authfullysimple.NewClientStore(tx)

							// Add a new client
							name := c.String("name")
							redirectURIs := c.StringSlice("redirect-uri")
							scopes := c.StringSlice("scope")
							client := &authfullysimple.DefaultClient{
								Name:         name,
								RedirectURIs: redirectURIs,
								Scopes:       scopes,
							}

							// Create a new client
							err = cs.Create(client)
							if err != nil {
								logger.Error("Failed to create client", "error", err)
								return err
							}

							// Generate a client secret with some hash method. The secret itself
							// can be verified with the client ID.
							// FIXME: can be done with some encryption method instead of hashing.
							secret, err := authfullysimple.GenerateClientSecret(client.ID)
							if err != nil {
								logger.Error("Failed to generate client secret", "error", err)
								tx.Rollback()
								return err
							}

							if err = client.SetSecret(secret); err != nil {
								logger.Error("Failed to set client secret", "error", err)
								tx.Rollback()
								return err
							}

							if err = cs.Update(client.ID, client); err != nil {
								logger.Error("Failed to update client with secret", "error", err)
								tx.Rollback()
								return err
							}

							// Commit the transaction
							tx.Commit()

							// Client created successfully
							fmt.Println("Client created successfully.")
							fmt.Printf("CLIENT_ID=%s\nCLIENT_SECRET=%s", client.GetID(), secret)
							return nil
						},
					},
					{
						Name: "check-secret",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "id",
								Usage:    "Client ID of the client",
								Required: true,
							},
							&cli.StringFlag{
								Name:     "secret",
								Usage:    "Client secret of the client",
								Required: true,
							},
						},
						Action: func(c *cli.Context) error {
							// Initialize the database
							db := getDatabase("auth-server.sqlite3", gormLogger, logger)

							// Create a new client store
							cs := authfullysimple.NewClientStore(db)

							// Check if the client exists
							clientID := c.String("id")
							client, err := cs.GetClientByID(clientID)
							if err != nil {
								logger.Error("Failed to get client by ID", "error", err)
								return err
							}

							// Check if the client secret is correct
							clientSecret := c.String("secret")
							err = client.CheckSecret(clientSecret)
							if err != nil {
								logger.Error("Failed to check client secret", "error", err)
								return err
							}

							// Client secret is correct
							logger.Info("Client secret is correct", "client_id", client.GetID())
							return nil
						},
					},
				},
			},
			{
				Name: "user",
				Subcommands: []*cli.Command{
					{
						Name: "create",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:     "email",
								Usage:    "Email of the user",
								Required: true,
							},
							&cli.StringFlag{
								Name:     "password",
								Usage:    "Password of the user",
								Required: true,
							},
						},
						Action: func(c *cli.Context) error {
							// Initialize the database
							db, err := gorm.Open(sqlite.Open("auth-server.sqlite3"), &gorm.Config{
								Logger: gormLogger,
							})
							if err != nil {
								logger.Error("Failed to connect database", "error", err)
								panic(err)
							}
							logger.Info("connected to database")

							// Create a new user store
							us := authfullysimple.NewUserStore(db)

							// Add a new user
							email := c.String("email")
							password := c.String("password")
							user := &authfullysimple.DefaultUser{
								Email: email,
							}
							user.SetPassword(password)

							err = us.Create(user)
							if err != nil {
								logger.Error("Failed to create user", "error", err)
								return err
							}

							// User created successfully
							logger.Info("User created", "user", *user)
							return nil
						},
					},
				},
			},
		},
	}).Run(os.Args)
}

type JwtCookieSessionHandler struct {
	cookieCreator  func(r *http.Request) *http.Cookie
	privateKey     *ecdsa.PrivateKey
	signingMethod  jwt.SigningMethod
	authReqDecoder authfully.AuthorizationRequestDecoder
}

func NewJwtCookieSessionHandler(
	cookieCreator func(r *http.Request) *http.Cookie,
	privateKey *ecdsa.PrivateKey,
	signingMethod jwt.SigningMethod,
	authReqDecoder authfully.AuthorizationRequestDecoder,
) *JwtCookieSessionHandler {
	return &JwtCookieSessionHandler{
		cookieCreator:  cookieCreator,
		privateKey:     privateKey,
		signingMethod:  signingMethod,
		authReqDecoder: authReqDecoder,
	}
}

func (h *JwtCookieSessionHandler) GetSession(r *http.Request) (*authfully.AuthSession, error) {
	// Get the cookie from the request
	cookie, err := r.Cookie(h.cookieCreator(r).Name)
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, nil // No cookie found
		}
		return nil, err // Other error
	}

	// Parse the JWT token from the cookie
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return h.privateKey.Public(), nil
	})
	if err != nil {
		return nil, err
	}

	// Check if the token is valid
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("malformatted token claims")
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Parse authorization request from the claims
	authRequestQueryRaw, ok := claims["auth_request"]
	if !ok {
		return nil, fmt.Errorf("auth_request claim not set")
	}
	authRequestQueryStr, ok := authRequestQueryRaw.(string)
	if !ok {
		return nil, fmt.Errorf("malformatted auth_request claim (%v)", claims["auth_request"])
	}
	authRequestQuery, err := url.ParseQuery(authRequestQueryStr)
	if err != nil {
		return nil, fmt.Errorf("malformatted auth_request claim: %v", err)
	}

	// Parse user ID from the claims, if set
	userId := ""
	userIdRaw, ok := claims["user_id"]
	if ok {
		if userId, ok = userIdRaw.(string); !ok {
			return nil, fmt.Errorf("malformatted user_id claim (%v)", claims["user_id"])
		}
	}

	// Create a new AuthSession from the claims
	ar, err := h.authReqDecoder.Decode(authRequestQuery)
	if err != nil {
		return nil, fmt.Errorf("malformatted auth_request claim: %v", err)
	}
	session := &authfully.AuthSession{
		UserID:               userId,
		AuthorizationRequest: ar,
	}

	return session, nil
}

func (h *JwtCookieSessionHandler) SetSession(w http.ResponseWriter, r *http.Request, session *authfully.AuthSession) error {
	// Create a new JWT token
	claims := jwt.MapClaims{
		"auth_request": session.AuthorizationRequest.Query().Encode(),
	}
	if session.UserID != "" {
		claims["user_id"] = session.UserID
	}
	token := jwt.NewWithClaims(h.signingMethod, claims)

	// Sign the token with the private key
	signedToken, err := token.SignedString(h.privateKey)
	if err != nil {
		return err
	}

	// Set the cookie in the response
	c := h.cookieCreator(r)
	c.Value = signedToken
	c.Expires = session.ExpiresAt
	http.SetCookie(w, c)

	return nil
}

func (h *JwtCookieSessionHandler) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	// Create a new cookie with the same name and set the MaxAge to -1
	c := h.cookieCreator(r)
	c.MaxAge = -1
	http.SetCookie(w, c)

	return nil
}
