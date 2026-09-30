FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /out/mimikoutz-linux-amd64 .
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o /out/mimikoutz-windows-amd64.exe .
RUN CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o /out/mimikoutz-darwin-arm64 .

FROM alpine:3.19
COPY --from=builder /out/ /dist/
COPY powershell/ /dist/powershell/
ENTRYPOINT ["cp", "-r", "/dist/.", "/output/"]
