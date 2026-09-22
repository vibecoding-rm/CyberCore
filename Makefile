.PHONY: install test create-api-key migrate run compose-up compose-down

install:
	python3 -m pip install -r requirements.txt

test:
	python3 -m pytest -q

create-api-key:
	python3 -m scripts.create_api_credential local-operator

migrate:
	python3 -m scripts.migrate_db

run:
	uvicorn app.main:app --reload --host 127.0.0.1 --port 8080

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down
