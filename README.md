# AI-based Anomaly Detection in Cybersecurity Networks

## 📌 Overview
This project is a web-based anomaly detection system that uses machine learning algorithms like **Isolation Forest** and **Logistic Regression** to detect suspicious activity in network traffic. Built using Python and Flask.

## 💡 Features
- Real-time input of network data (or upload logs)
- Detection using trained ML models
- Dashboard to visualize alerts and results
- Lightweight Flask web app

## ⚙️ ML Techniques Used
- **Isolation Forest**: For unsupervised anomaly detection
- **Logistic Regression**: For binary classification of network events

## 🚀 Tech Stack
- Python
- Flask
- Scikit-learn
- HTML/CSS (Bootstrap or custom)
- Optional: SQLite/PostgreSQL for logs

## 🔧 Setup Instructions
1. Clone this repo:
https://github.com/SyntaxError-Natsu/Anomaly-detection.git
cd Anomaly-detection

2. Install dependencies:
pip install -r requirements.txt

3. Run the prepare model file:
python prepare_model.py

4. Run the Flask app:
python app.py
