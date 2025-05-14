module github.com/authfully/authfully/simple-suite

go 1.24.1

require (
	github.com/authfully/authfully v0.0.0-20250425153844-2dd236a58413
	github.com/google/uuid v1.6.0
	github.com/joho/godotenv v1.5.1
	github.com/urfave/cli/v2 v2.27.6
	gorm.io/driver/sqlite v1.5.7
	gorm.io/gorm v1.25.12
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
)

replace github.com/authfully/authfully => ../.
