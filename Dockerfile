# Build Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# Build Backend
FROM golang:1.21-alpine AS backend-builder
WORKDIR /app
COPY backend/go.mod ./
# COPY backend/go.sum ./ # We don't have this locally yet
COPY backend/ .
# Check if dependencies need to be downloaded/tidied since we lack go.sum
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o server main.go

# Final Stage
FROM alpine:latest
WORKDIR /root/
COPY --from=backend-builder /app/server .
COPY --from=frontend-builder /app/dist ./dist

ENV PORT=8080
EXPOSE 8080
CMD ["./server"]
