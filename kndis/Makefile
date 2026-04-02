# KNDIS - Konoha National Digital Identity System
# Makefile for development and deployment

.PHONY: all build test clean dev deploy docker-build docker-push k8s-deploy

# Variables
DOCKER_REGISTRY ?= localhost:5000
K8S_NAMESPACE ?= kndis
VERSION ?= latest

# Default target
all: build

# Build all services
build:
	@echo "Building KNDIS services..."
	go build -o bin/k-idp ./services/k-idp/main.go
	go build -o bin/spid-service ./services/spid-service/main.go
	go build -o bin/consent-service ./services/consent-service/main.go
	go build -o bin/gateway ./services/gateway/main.go
	go build -o bin/audit-log ./services/audit-log/main.go
	go build -o bin/token-service ./services/token-service/main.go
	go build -o bin/credential-issuer ./services/credential-issuer/main.go
	@echo "Build complete!"

# Run tests
test:
	@echo "Running tests..."
	go test -v ./libs/...
	go test -v ./services/...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	docker-compose down -v

# Run all services locally with docker-compose
dev:
	@echo "Starting KNDIS services with docker-compose..."
	docker-compose up --build -d
	@echo "Services starting..."
	@echo "K-IdP: http://localhost:8080"
	@echo "SPID Service: http://localhost:8081"
	@echo "Consent Service: http://localhost:8082"
	@echo "Gateway: http://localhost:8083"
	@echo "Audit Log: http://localhost:8084"
	@echo "Token Service: http://localhost:8088"
	@echo "Credential Issuer: http://localhost:8089"

# Stop docker-compose services
dev-stop:
	@echo "Stopping KNDIS services..."
	docker-compose down

# View logs from all services
logs:
	docker-compose logs -f

# Build Docker images
docker-build:
	@echo "Building Docker images..."
	docker build -t $(DOCKER_REGISTRY)/kndis/k-idp:$(VERSION) -f services/k-idp/Dockerfile .
	docker build -t $(DOCKER_REGISTRY)/kndis/spid-service:$(VERSION) -f services/spid-service/Dockerfile .
	docker build -t $(DOCKER_REGISTRY)/kndis/consent-service:$(VERSION) -f services/consent-service/Dockerfile .
	docker build -t $(DOCKER_REGISTRY)/kndis/gateway:$(VERSION) -f services/gateway/Dockerfile .
	docker build -t $(DOCKER_REGISTRY)/kndis/audit-log:$(VERSION) -f services/audit-log/Dockerfile .
	docker build -t $(DOCKER_REGISTRY)/kndis/token-service:$(VERSION) -f services/token-service/Dockerfile .
	docker build -t $(DOCKER_REGISTRY)/kndis/credential-issuer:$(VERSION) -f services/credential-issuer/Dockerfile .

# Push Docker images to registry
docker-push: docker-build
	@echo "Pushing Docker images..."
	docker push $(DOCKER_REGISTRY)/kndis/k-idp:$(VERSION)
	docker push $(DOCKER_REGISTRY)/kndis/spid-service:$(VERSION)
	docker push $(DOCKER_REGISTRY)/kndis/consent-service:$(VERSION)
	docker push $(DOCKER_REGISTRY)/kndis/gateway:$(VERSION)
	docker push $(DOCKER_REGISTRY)/kndis/audit-log:$(VERSION)
	docker push $(DOCKER_REGISTRY)/kndis/token-service:$(VERSION)
	docker push $(DOCKER_REGISTRY)/kndis/credential-issuer:$(VERSION)

# Deploy to Kubernetes
k8s-deploy:
	@echo "Deploying to Kubernetes..."
	kubectl apply -f infra/k8s/namespace.yaml
	kubectl apply -f infra/k8s/configmap.yaml
	kubectl apply -f infra/k8s/k-idp-deployment.yaml
	kubectl apply -f infra/k8s/spid-service-deployment.yaml
	kubectl apply -f infra/k8s/consent-service-deployment.yaml
	kubectl apply -f infra/k8s/gateway-deployment.yaml
	@echo "Deployment complete!"

# Delete Kubernetes deployment
k8s-delete:
	@echo "Deleting Kubernetes deployment..."
	kubectl delete -f infra/k8s/

# Get Kubernetes pod status
k8s-status:
	kubectl get pods -n $(K8S_NAMESPACE)

# Get Kubernetes service status
k8s-services:
	kubectl get services -n $(K8S_NAMESPACE)

# View Kubernetes logs
k8s-logs:
	kubectl logs -n $(K8S_NAMESPACE) -l app=k-idp --tail=100 -f

# Port forward for local testing
k8s-port-forward:
	@echo "Port forwarding K-IdP to localhost:8080..."
	kubectl port-forward -n $(K8S_NAMESPACE) svc/k-idp 8080:8080

# Format Go code
fmt:
	go fmt ./...

# Run Go vet
vet:
	go vet ./...

# Run linter
lint:
	golangci-lint run ./...

# Download dependencies
deps:
	go mod download
	go mod tidy

# Generate code (if using generators)
generate:
	go generate ./...

# Security scan
security-scan:
	gosec ./...

# Run integration tests
integration-test:
	@echo "Running integration tests..."
	./scripts/integration-test.sh

# Demo: Complete OAuth2 flow
demo-oauth2:
	@echo "Running OAuth2 demo flow..."
	./scripts/demo-oauth2.sh

# Demo: Bank account opening flow
demo-bank:
	@echo "Running bank account opening demo..."
	./scripts/demo-bank-account.sh

# Help
help:
	@echo "KNDIS - Konoha National Digital Identity System"
	@echo ""
	@echo "Available targets:"
	@echo "  make build           - Build all services"
	@echo "  make test            - Run unit tests"
	@echo "  make test-coverage   - Run tests with coverage report"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make dev             - Start services with docker-compose"
	@echo "  make dev-stop        - Stop docker-compose services"
	@echo "  make logs            - View service logs"
	@echo "  make docker-build    - Build Docker images"
	@echo "  make docker-push     - Push Docker images to registry"
	@echo "  make k8s-deploy      - Deploy to Kubernetes"
	@echo "  make k8s-delete      - Delete Kubernetes deployment"
	@echo "  make k8s-status      - Check Kubernetes pod status"
	@echo "  make k8s-logs        - View Kubernetes logs"
	@echo "  make fmt             - Format Go code"
	@echo "  make vet             - Run go vet"
	@echo "  make lint            - Run linter"
	@echo "  make deps            - Download dependencies"
	@echo "  make demo-oauth2     - Run OAuth2 demo"
	@echo "  make demo-bank       - Run bank account demo"
	@echo "  make help            - Show this help"