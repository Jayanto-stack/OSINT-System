# AI-Powered OSINT Risk Intelligence System

An open-source OSINT tool that combines real-time web intelligence, breach databases, network scanning, and local AI analysis to generate comprehensive digital risk reports.

## Features
- Email registration detection (Holehe)
- Data Breach lookup (LeakCheck.io)
- Network exposure scanning (Shodan)
- Email intelligence (Hunter.io)
- Social media profile finder (Sherlock)
- Phone number intelligence (NumVerify)
- AI-powered risk analysis (Ollama/Llama3 - runs locally)
- Scan history with risk trend graphs

## Requirements
- Python 3.11+
- Ollama installed with llama3 model
- API keys (see configuration)

## Installation
```bash
git clone https://github.com/YOUR_USERNAME/OSINT-System.git
cd OSINT-System/backend
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
```
## Configuration
Copy `.env.example` to `.env` and fill in your API keys:
```bash
cp .env.example backend/.env
```

## Usage
```bash
cd backend
unicorn main:app --reload --port 8000
```
Open `http://127.0.0.1:8000

## API keys needed
| Service | Free Tier | Link |
|---|---|---|---|
| LeakCheck | Yes  | leakcheck.io |
| Shodan  | Yes (limited) | shodan.io |
| Hunter.io  | 25/month | hunter.io |
| NumVerrify | 100/month  | numverify.com |

## Disclainer
For authorized and educational use only.

osint-risk-system/
```
│
├── backend/
│   ├── main.py
│   ├── routes/
│   ├── services/
│   ├── osint/
│   ├── ai/
│   └── database/
│
├── frontend/
│   ├── index.html
│   ├── css/
│   └── js/
│
├── requirements.txt
├── README.md
└── .gitignore
```
