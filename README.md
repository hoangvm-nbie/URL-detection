# AI Cyber Shield - Phishing URL Detection

AI Cyber Shield is a machine learning-based phishing URL detection platform that combines cybersecurity feature engineering and web technologies to identify malicious URLs in real time.

---

## Quick Access

🌐 Live Demo:

https://nhap-mon-ai-production.up.railway.app/#scanner

---

# Overview

The system analyzes URL structures, domain characteristics, and website behaviors to detect phishing websites.

It integrates machine learning models with a Flask-based web application, allowing users to evaluate URL security risks through an interactive interface.

---

# Key Features

- Real-time phishing URL detection
- URL feature extraction
- Domain analysis
- Website behavior analysis
- Risk score calculation
- Interactive web dashboard
- Detection history tracking
- Model performance visualization
- User feedback system

---

# System Architecture

```
User Input URL
        |
        v
Frontend Interface
        |
        v
Flask Backend API
        |
        v
Feature Extraction Engine
        |
        v
Machine Learning Models
(Naive Bayes / Random Forest)
        |
        v
Risk Assessment
        |
        v
Detection Result
```

---

# Dataset

Total URLs:

```
41,536
```

Classification:

```
Binary Classification
```

Classes:

- Legitimate URLs
- Phishing URLs

Data preprocessing:

- Feature extraction
- Data balancing using SMOTE

---

# Machine Learning Models

| Model | Accuracy | Precision | Recall | F1-Score |
|---|---|---|---|---|
| Naive Bayes | 84.76% | 93.32% | 87.24% | 90.17% |
| Random Forest | 93.27% | 97.55% | 93.96% | 95.72% |

Random Forest achieved the best performance and is used as the main detection model.

---

# Project Structure

```
AI-Cyber-Shield/
│
├── data/
│   └── traindata.csv
│
├── templates/
│   ├── index.html
│   
├── static/
│   ├── css/style.css
│   └── js/app.js
│
├── models/
│   ├── random_forest_model.pkl
│   └── naive_bayes_model.pkl
│
├── results/
│   ├── bieu_do_dac_trung.png
│   ├── ket_qua_so_sanh.csv
│   ├── ma_tran_nham_lan_nb.png
│   └── ma_tran_nham_lan_rf.png
│
├── routes/
│   ├── scan.py
│   ├── history.py
│   ├── feedback.py
│   └── performance.py
│
├── src/
│   ├── feature_extractor.py
│   └── train.py
│
├── app.py
├── config.py
└── requirements.txt
```

---

# Installation

## 1. Clone Repository

```bash
git clone https://github.com/Hoangvm206/URL-detection.git

cd URL-detection
```

---

## 2. Create Virtual Environment

### Windows

```bash
python -m venv venv

venv\Scripts\activate
```

### Linux / macOS

```bash
python -m venv venv

source venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Check Required Files

Before running, make sure these files exist:

```
models/
├── random_forest_model.pkl
└── naive_bayes_model.pkl


data/
└── traindata.csv
```

---

# Run Application

Start Flask:

```bash
python app.py
```

The application will run at:

```
http://localhost:5000
```

---

# Usage

1. Open the website

```
http://localhost:5000
```

2. Enter a URL

Example:

```
https://google.com
```

3. Click scan

The system will:

- Extract URL features
- Analyze URL characteristics
- Run ML models
- Calculate risk score
- Display security result

---

# API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| /api/scan | POST | Analyze URL |
| /api/history | GET | Get scan history |
| /api/feedback | POST | Submit feedback |
| /api/performance | GET | View model performance |

---

# Training

To retrain the models:

```bash
python src/train.py
```

Generated models:

```
models/
```

---

# Technologies Used

## Cybersecurity

- Phishing Detection
- URL Analysis
- Domain Analysis
- Security Feature Engineering

## Machine Learning

- Scikit-learn
- Random Forest
- Naive Bayes
- SMOTE
- Pandas
- NumPy

## Software Development

- Python
- Flask
- HTML
- CSS
- JavaScript
- Railway Deployment

---

# Team

| Member | Role |
|---|---|
| Vu Minh Hoang | Team Leader |
| Vu Minh Tu | Team Member |
| Vu Tien Thanh | Team Member |
| Ngo Duc Thang | Team Member |

---

# License

This project was developed for educational and research purposes.
