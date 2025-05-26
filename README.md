# 🔒 AI-based Anomaly Detection in Cybersecurity Networks

This project is a web-based anomaly detection system that uses machine learning algorithms like **Isolation Forest** and **Logistic Regression** to detect suspicious activity in network traffic. Built using Python and Flask for real-time cybersecurity monitoring and threat detection.

## 📌 Features

- 🔍 **Real-time Network Monitoring**: Input network data or upload logs for instant analysis
- 🤖 **Machine Learning Detection**: Advanced ML algorithms for accurate anomaly identification
- 📊 **Interactive Dashboard**: Visualize alerts, results, and network statistics
- ⚡ **Lightweight Architecture**: Fast and efficient Flask-based web application
- 📈 **Data Visualization**: Comprehensive charts and graphs for threat analysis
- 🚨 **Alert System**: Real-time notifications for detected anomalies

## 💠 ML Techniques Used

**Unsupervised Learning:**
- **Isolation Forest**: Advanced anomaly detection for identifying outliers in network behavior

**Supervised Learning:**
- **Logistic Regression**: Binary classification for categorizing network events as normal or suspicious

## 🚀 Tech Stack

**Backend:**
- Python
- Flask
- Scikit-learn
- Pandas & NumPy

**Frontend:**
- HTML/CSS
- Bootstrap
- JavaScript

**Database:**
- SQLite/PostgreSQL (for logs storage)

## 🔧 Getting Started

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Git

### Installation

**1. Clone the repository:**
```
git clone https://github.com/SyntaxError-Natsu/Anomaly-detection.git
cd Anomaly-detection
```

**2. Install dependencies:**
```
pip install -r requirements.txt
```

**3. Prepare the ML models:**
```
python prepare_model.py
```

Access the application at `http://localhost:5000`

## 📁 Project Structure
```
Anomaly-Detection/
├── app.py # Main Flask application
├── prepare_model.py # ML model preparation script
├── models/
│ ├── isolation_forest.pkl
│ └── logistic_regression.pkl
├── templates/
│ ├── index.html
│ ├── dashboard.html
│ └── results.html
├── static/
│ ├── css/
│ ├── js/
│ └── images/
├── data/
│ └── network_logs/
├── requirements.txt
└── README.md
```

## 📸 Screenshots

<div style="display: flex; justify-content: center; flex-wrap: wrap; gap: 20px; margin-top: 20px;">
  <div style="width: 300px; text-align: center;">
    <p style="margin-top: 10px; font-weight: 500; text-align: center;">Home Page:</p>
    <img src="https://github.com/user-attachments/assets/1e2f43a4-471e-4f16-9a37-697a1669deb4" alt="Home Page" style="width: 100%; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
  </div>
  <div style="width: 300px; text-align: center;">
    <p style="margin-top: 10px; font-weight: 500; text-align: center;">Dashboard 1:</p>
    <img src="https://github.com/user-attachments/assets/5ecd261c-03ff-4cfb-a9ab-928506479201" alt="Dashboard 1" style="width: 100%; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
  </div>
  <div style="width: 300px; text-align: center;">
    <p style="margin-top: 10px; font-weight: 500; text-align: center;">Dashboard 2:</p>
    <img src="https://github.com/user-attachments/assets/d52712b1-bc3e-4cd1-ba5e-c4817f996fe6" alt="Dashboard 2" style="width: 100%; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
  </div>
  <div style="width: 300px; text-align: center;">
    <p style="margin-top: 10px; font-weight: 500; text-align: center;">Visualization 1:</p>
    <img src="https://github.com/user-attachments/assets/1cb88c20-3719-4ff4-a593-e8a94cb77ad8" alt="Visualization 1" style="width: 100%; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
  </div>
  <div style="width: 300px; text-align: center;">
    <p style="margin-top: 10px; font-weight: 500; text-align: center;">Visualization 2:</p>
    <img src="https://github.com/user-attachments/assets/65183176-c29a-46b5-9282-3f0de31e1c8c" alt="Visualization 2" style="width: 100%; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
  </div>
</div>

## 🔬 How It Works

1. **Data Collection**: Network traffic data is collected through real-time input or log file uploads
2. **Preprocessing**: Raw data is cleaned and normalized for ML model consumption
3. **Anomaly Detection**: Isolation Forest identifies unusual patterns in network behavior
4. **Classification**: Logistic Regression categorizes events as normal or suspicious
5. **Visualization**: Results are displayed through interactive dashboards and charts
6. **Alerting**: Suspicious activities trigger real-time alerts for immediate response

## 🤝 Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License. See the [`LICENSE`](LICENSE) file for details.

## 👨‍💻 Developer

Developed with ❤️ by [Priyanshu Kumar](https://github.com/SyntaxError-Natsu)

---

⭐ Star this repository if you found it helpful!
