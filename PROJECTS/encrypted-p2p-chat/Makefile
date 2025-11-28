# ⒸAngelaMos | 2025
# Makefile

.PHONY: help setup setup-backend setup-frontend env dev prod build-dev build-prod up-dev up-prod down-dev down-prod logs-dev logs-prod test-backend clean

help:
	@echo "Encrypted P2P Chat - Makefile Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make setup              - Complete project setup (backend + frontend)"
	@echo "  make setup-backend      - Setup backend (venv, install deps)"
	@echo "  make setup-frontend     - Setup frontend (install npm deps)"
	@echo "  make env                - Copy .env.example to .env files"
	@echo ""
	@echo "Development:"
	@echo "  make dev                - Start development environment"
	@echo "  make build-dev          - Build development Docker images"
	@echo "  make up-dev             - Start development containers"
	@echo "  make down-dev           - Stop development containers"
	@echo "  make logs-dev           - Follow development logs"
	@echo ""
	@echo "Production:"
	@echo "  make prod               - Start production environment"
	@echo "  make build-prod         - Build production Docker images"
	@echo "  make up-prod            - Start production containers"
	@echo "  make down-prod          - Stop production containers"
	@echo "  make logs-prod          - Follow production logs"
	@echo ""
	@echo "Testing:"
	@echo "  make test-backend       - Run backend tests"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean              - Remove all containers, volumes, and build artifacts"

setup: setup-backend setup-frontend env
	@echo "Setup complete!"

setup-backend:
	@echo "Setting up backend..."
	cd backend && python3 -m venv ../.venv
	. .venv/bin/activate && cd backend && pip install -e .[dev]
	@echo "Backend setup complete!"

setup-frontend:
	@echo "Setting up frontend..."
	cd frontend && npm install
	@echo "Frontend setup complete!"

env:
	@echo "Creating .env files..."
	@if [ ! -f .env ]; then cp .env.example .env; echo "Created root .env"; fi
	@if [ ! -f frontend/.env ]; then cp frontend/.env.example frontend/.env; echo "Created frontend/.env"; fi
	@echo ".env files created! Please update with your values."

dev: build-dev up-dev

build-dev:
	@echo "Building development Docker images..."
	docker compose -f docker-compose.dev.yml build

up-dev:
	@echo "Starting development environment..."
	docker compose -f docker-compose.dev.yml up -d
	@echo "Development environment started!"
	@echo "Frontend: http://localhost:5173"
	@echo "Backend: http://localhost:8000"
	@echo "Nginx: http://localhost"

down-dev:
	@echo "Stopping development environment..."
	docker compose -f docker-compose.dev.yml down

logs-dev:
	docker compose -f docker-compose.dev.yml logs -f

prod: build-prod up-prod

build-prod:
	@echo "Building production Docker images..."
	docker compose -f docker-compose.prod.yml build

up-prod:
	@echo "Starting production environment..."
	docker compose -f docker-compose.prod.yml up -d
	@echo "Production environment started!"
	@echo "Application: http://localhost"

down-prod:
	@echo "Stopping production environment..."
	docker compose -f docker-compose.prod.yml down

logs-prod:
	docker compose -f docker-compose.prod.yml logs -f

test-backend:
	@echo "Running backend tests..."
	. .venv/bin/activate && cd backend && python -m pytest tests/ -v

clean:
	@echo "Cleaning up..."
	docker compose -f docker-compose.dev.yml down -v
	docker compose -f docker-compose.prod.yml down -v
	rm -rf frontend/node_modules
	rm -rf frontend/dist
	rm -rf backend/.venv
	rm -rf backend/__pycache__
	rm -rf backend/.pytest_cache
	rm -rf backend/.mypy_cache
	rm -rf backend/.ruff_cache
	@echo "Cleanup complete!"
