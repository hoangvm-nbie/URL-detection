# AI Cyber Shield - Phishing URL Detection

AI Cyber Shield is a machine learning-based phishing URL detection platform that combines cybersecurity feature engineering and web technologies to identify malicious URLs in real time.

## Quick Access

🌐 Live Demo: https://nhap-mon-ai-production.up.railway.app/#scanner

📂 GitHub Repository: https://github.com/Hoangvm206/URL-detection

---

## Overview

The system analyzes URL structures, domain characteristics, and website behaviors to detect phishing websites. It integrates machine learning models with a Flask-based web application, allowing users to assess URL risks through an interactive interface.

### Key Features

* Real-time phishing URL detection
* Security-oriented feature engineering
* URL, domain, and website behavior analysis
* Risk score assessment
* Web-based dashboard
* Detection history and performance tracking

---

## System Architecture

```text
User Input URL
      │
      ▼
Frontend Interface
      │
      ▼
Flask Backend API
      │
      ▼
Feature Extraction Engine
      │
      ▼
Machine Learning Models
(Naive Bayes / Random Forest)
      │
      ▼
Risk Assessment
      │
      ▼
Detection Result
```

---

## Dataset

* Total URLs: 41,536
* Classification Type: Binary Classification

  * Legitimate URLs
  * Phishing URLs
* Data balancing using SMOTE

---

## Machine Learning Models

| Model         | Accuracy | Precision | Recall | F1-Score |
| ------------- | -------- | --------- | ------ | -------- |
| Naive Bayes   | 84.76%   | 93.32%    | 87.24% | 90.17%   |
| Random Forest | 93.27%   | 97.55%    | 93.96% | 95.72%   |

Random Forest achieved the best performance and was selected as the primary detection model.

---

## Project Structure

```text
AI-Cyber-Shield/
│
├── data/               # Training datasets
├── frontend/           # Frontend assets
├── models/             # Trained ML models
├── results/            # Evaluation results
├── routes/             # API endpoints
├── src/                # Training and feature extraction
│
├── app.py              # Flask application
├── config.py           # Application configuration
├── requirements.txt
└── README.md
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Hoangvm206/URL-detection.git
cd URL-detection
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

The application will be available at:

```text
http://localhost:5000
```

---

## Technologies Used

### Cybersecurity

* Phishing Detection
* URL Analysis
* Domain Reputation Analysis
* DNS Validation
* Security Feature Engineering

### Machine Learning

* Scikit-learn
* Random Forest
* Naive Bayes
* SMOTE

### Software Development

* Python
* Flask
* HTML/CSS/JavaScript
* Railway Deployment

---

## Team

| Member        | Role                                             |
| ------------- | ------------------------------------------------ |
| Vu Minh Hoang | Team Leader |
| Vu Minh Tu    | Team Member                                      |
| Vu Tien Thanh | Team Member                                      |
| Ngo Duc Thang | Team Member                                      |

---

## License

This project was developed for educational and research purposes.
