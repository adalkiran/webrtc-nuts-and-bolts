echo "Downloading dependent Go modules..."
go mod download -x
echo "Running application..."
cd src
go run .