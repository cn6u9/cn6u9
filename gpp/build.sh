#go install github.com/wailsapp/wails/v2/cmd/wails@latest
#wails build -m -trimpath -tags webkit2_41,with_quic

npm install
npm run build
cd ..
export NODE_OPTIONS="--max-old-space-size=4096"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 wails build -tags with_gvisor --skipbindings