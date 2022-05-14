echo "Downloading dependent Go modules..."
go mod download -x
echo "Running into Waiting loop..."
tail -f /dev/null