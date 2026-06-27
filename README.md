# Argowei

Argowei is a self-hosted network intelligence and device management platform
for homelabs and private infrastructure.

## Development

Start the application with Docker Compose:

```bash
docker compose up --build
```

The dashboard is available at <http://localhost:4200> and the API documentation
at <http://localhost:8000/docs>.

To run the services locally, start the backend first:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then start the frontend in a separate terminal:

```bash
cd frontend
npm install
npm start
```

## License

[MIT](LICENSE)
