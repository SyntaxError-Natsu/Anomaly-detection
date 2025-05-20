import os
import pickle
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
import json
from flask import Flask, render_template, request, jsonify, url_for, redirect, flash
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, roc_curve, auc
import io
import base64
from datetime import datetime, timedelta
from io import BytesIO

app = Flask(__name__)
app.secret_key = "network_anomaly_detection_secret_key"

def create_correlation_heatmap(df, figsize=(10, 6)):
    fig, ax = plt.subplots(figsize=figsize)
    corr_matrix = df.corr()
    mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
    sns.heatmap(
        corr_matrix,
        mask=mask,
        annot=False,
        cmap='coolwarm',
        linewidths=0.5,
        ax=ax,
        cbar_kws={'shrink': 0.8}
    )
    ax.set_title('Feature Correlation Heatmap')
    plt.tight_layout()
    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    img_str = base64.b64encode(buf.read()).decode('utf-8')
    return img_str

# Helper function to convert numpy types to Python native types
def convert_numpy_types(obj):
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj

# Global variables
MODEL_PATH = os.path.join('models', 'anomaly_model.pkl')
SCALER_PATH = os.path.join('models', 'scaler.pkl')
ENCODER_PATH = os.path.join('models', 'encoder.pkl')
TRAIN_DATA_PATH = "Train.txt"
TEST_DATA_PATH = "Test.txt"

# Define column names
COLUMN_NAMES = ["duration", "protocoltype", "service", "flag", "srcbytes", "dstbytes", "land", 
               "wrongfragment", "urgent", "hot", "numfailedlogins", "loggedin", "numcompromised", 
               "rootshell", "suattempted", "numroot", "numfilecreations", "numshells", 
               "numaccessfiles", "numoutboundcmds", "ishostlogin", "isguestlogin", "count", 
               "srvcount", "serrorrate", "srvserrorrate", "rerrorrate", "srvrerrorrate", 
               "samesrvrate", "diffsrvrate", "srvdiffhostrate", "dsthostcount", "dsthostsrvcount", 
               "dsthostsamesrvrate", "dsthostdiffsrvrate", "dsthostsamesrcportrate", 
               "dsthostsrvdiffhostrate", "dsthostserrorrate", "dsthostsrvserrorrate", 
               "dsthostrerrorrate", "dsthostsrvrerrorrate", "attack", "lastflag"]

FEATURE_NAMES = COLUMN_NAMES[:-2]  # Exclude 'attack' and 'lastflag'

# Load model and preprocessing components
def load_model_components():
    global model, scaler, encoder_dict
    
    # Check if model directory exists
    if not os.path.exists('models'):
        os.makedirs('models')
        flash("Model directory created. Please run prepare_model.py to train the model.", "warning")
        return False
    
    # Check if model files exist
    if not (os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH) and os.path.exists(ENCODER_PATH)):
        flash("Model files not found. Please run prepare_model.py to train the model.", "warning")
        return False
    
    try:
        # Load model
        with open(MODEL_PATH, 'rb') as file:
            model = pickle.load(file)
        
        # Load scaler
        with open(SCALER_PATH, 'rb') as file:
            scaler = pickle.load(file)
        
        # Load encoder dictionary
        with open(ENCODER_PATH, 'rb') as file:
            encoder_dict = pickle.load(file)
        
        return True
    except Exception as e:
        flash(f"Error loading model components: {str(e)}", "danger")
        return False

# Load sample data for visualizations
def load_sample_data():
    try:
        # Load a small sample of data for visualizations
        train_data = pd.read_csv(TRAIN_DATA_PATH, sep=",", names=COLUMN_NAMES, nrows=5000)
        test_data = pd.read_csv(TEST_DATA_PATH, sep=",", names=COLUMN_NAMES, nrows=1000)
        
        # Add binary attack column (normal=0, attack=1)
        train_data['binary_attack'] = train_data['attack'].apply(lambda x: 0 if x == 'normal' else 1)
        test_data['binary_attack'] = test_data['attack'].apply(lambda x: 0 if x == 'normal' else 1)
        
        return train_data, test_data
    except Exception as e:
        flash(f"Error loading sample data: {str(e)}", "danger")
        return None, None

# Map attack types to categories
def map_attack_category(attack):
    dos_attacks = ['neptune', 'smurf', 'pod', 'teardrop', 'land', 'back', 'apache2', 'udpstorm', 'processtable', 'mailbomb']
    probe_attacks = ['portsweep', 'ipsweep', 'nmap', 'satan', 'saint', 'mscan']
    r2l_attacks = ['guess_passwd', 'ftp_write', 'imap', 'phf', 'multihop', 'warezmaster', 'warezclient', 'spy', 'xlock', 'xsnoop', 'snmpguess', 'snmpgetattack', 'httptunnel', 'sendmail', 'named']
    u2r_attacks = ['buffer_overflow', 'loadmodule', 'rootkit', 'perl', 'sqlattack', 'xterm', 'ps']
    
    if attack == 'normal':
        return 'normal'
    elif attack in dos_attacks:
        return 'dos'
    elif attack in probe_attacks:
        return 'probe'
    elif attack in r2l_attacks:
        return 'r2l'
    elif attack in u2r_attacks:
        return 'u2r'
    else:
        return 'unknown'

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    # Check if model is loaded
    if not load_model_components():
        return redirect(url_for('index'))
    
    # Load sample data
    train_data, test_data = load_sample_data()
    if train_data is None or test_data is None:
        return redirect(url_for('index'))
    
    numeric_cols = ['duration', 'srcbytes', 'dstbytes', 'count', 'serrorrate', 'rerrorrate', 'samesrvrate', 'dsthostcount']
    for col in numeric_cols:
        train_data[col] = pd.to_numeric(train_data[col], errors='coerce')
    heatmap_img = create_correlation_heatmap(train_data[numeric_cols], figsize=(10, 6))

    # Add attack category to datasets
    train_data['attack_category'] = train_data['attack'].apply(map_attack_category)
    test_data['attack_category'] = test_data['attack'].apply(map_attack_category)
    
    # Calculate metrics for dashboard
    metrics = {
        'accuracy': 0.95,  # Placeholder values - would be calculated from model evaluation
        'precision': 0.92,
        'recall': 0.94,
        'f1_score': 0.93,
        'total_traffic': len(test_data),
        'normal_traffic': len(test_data[test_data['attack'] == 'normal']),
        'anomalies': len(test_data[test_data['attack'] != 'normal']),
        'suspicious_traffic': len(test_data[test_data['serrorrate'] > 0.5])
    }
    
    # Generate visualizations
    visualizations = generate_dashboard_visualizations(train_data, test_data)
    
    # Generate timeline data
    timeline_labels = [(datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(14, 0, -1)]
    
    # Mock data for timeline
    dos_timeline = [np.random.randint(5, 30) for _ in range(14)]
    probe_timeline = [np.random.randint(3, 15) for _ in range(14)]
    r2l_timeline = [np.random.randint(0, 8) for _ in range(14)]
    u2r_timeline = [np.random.randint(0, 3) for _ in range(14)]
    
    # Attack distribution
    attack_counts = test_data['attack_category'].value_counts()
    attack_distribution = {
        'dos': int(attack_counts.get('dos', 0)),
        'probe': int(attack_counts.get('probe', 0)),
        'r2l': int(attack_counts.get('r2l', 0)),
        'u2r': int(attack_counts.get('u2r', 0)),
        'normal': int(attack_counts.get('normal', 0))
    }
    
    # Protocol distribution
    protocol_normal = [
        len(test_data[(test_data['protocoltype'] == 'tcp') & (test_data['attack'] == 'normal')]),
        len(test_data[(test_data['protocoltype'] == 'udp') & (test_data['attack'] == 'normal')]),
        len(test_data[(test_data['protocoltype'] == 'icmp') & (test_data['attack'] == 'normal')])
    ]
    
    protocol_anomalous = [
        len(test_data[(test_data['protocoltype'] == 'tcp') & (test_data['attack'] != 'normal')]),
        len(test_data[(test_data['protocoltype'] == 'udp') & (test_data['attack'] != 'normal')]),
        len(test_data[(test_data['protocoltype'] == 'icmp') & (test_data['attack'] != 'normal')])
    ]
    
    # Generate recent anomalies
    recent_anomalies = generate_recent_anomalies()
    
    return render_template('dashboard.html', 
                          metrics=metrics,
                          visualizations=visualizations,
                          timeline_labels=timeline_labels,
                          dos_timeline=dos_timeline,
                          probe_timeline=probe_timeline,
                          r2l_timeline=r2l_timeline,
                          u2r_timeline=u2r_timeline,
                          attack_distribution=attack_distribution,
                          protocol_normal=protocol_normal,
                          protocol_anomalous=protocol_anomalous,
                          recent_anomalies=recent_anomalies,
                          heatmap_img=heatmap_img)

# Detailed visualizations route
@app.route('/visualizations')
def visualizations():
    # Check if model is loaded
    if not load_model_components():
        return redirect(url_for('index'))
    
    # Load sample data
    train_data, _ = load_sample_data()
    if train_data is None:
        return redirect(url_for('index'))
    
    # Generate detailed visualizations
    visualizations = generate_detailed_visualizations(train_data)
    
    return render_template('visualizations.html', visualizations=visualizations)

# Prediction form route
@app.route('/predict', methods=['GET'])
def predict_form():
    # Check if model is loaded
    if not load_model_components():
        return redirect(url_for('index'))
    
    # Get example data for normal and attack cases
    normal_example, attack_example = get_example_data()
    
    # Get feature descriptions
    feature_descriptions = get_feature_descriptions()
    
    # Get protocol types, services and flags from encoder
    protocol_types = list(encoder_dict['protocoltype'].classes_) if 'protocoltype' in encoder_dict else ['tcp', 'udp', 'icmp']
    services = list(encoder_dict['service'].classes_) if 'service' in encoder_dict else ['http', 'ftp', 'smtp', 'telnet', 'private']
    flags = list(encoder_dict['flag'].classes_) if 'flag' in encoder_dict else ['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'S1', 'S2', 'S3', 'OTH']
    
    return render_template('predict.html', 
                           feature_names=FEATURE_NAMES,
                           normal_example=normal_example,
                           attack_example=attack_example,
                           feature_descriptions=feature_descriptions,
                           protocol_types=protocol_types,
                           services=services,
                           flags=flags)

# Prediction result route
@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Check if model is loaded
        if not load_model_components():
            return redirect(url_for('predict_form'))
        
        # Get form data
        input_data = {}
        for col in FEATURE_NAMES:
            input_data[col] = request.form.get(col, '0')
        
        # Convert to DataFrame
        input_df = pd.DataFrame([input_data])
        
        # Preprocess input
        processed_data = preprocess_input(input_df)
        
        # Make prediction
        prediction = model.predict(processed_data)[0]
        probability = model.predict_proba(processed_data)[0]
        
        # Force conversion
        prediction = int(prediction)
        probability = [float(p) for p in probability]
        
        # Determine attack type
        attack_type = "Unknown"
        if prediction == 1:
            if float(input_data.get('serrorrate', 0)) > 0.5:
                attack_type = "DoS (Denial of Service)"
            elif float(input_data.get('dsthostcount', 0)) > 200:
                attack_type = "Probe Attack"
            elif float(input_data.get('numfailedlogins', 0)) > 0:
                attack_type = "R2L (Remote to Local)"
            elif float(input_data.get('rootshell', 0)) > 0:
                attack_type = "U2R (User to Root)"
            else:
                attack_type = "Network Anomaly"
        else:
            attack_type = "Normal Traffic"
        
        # Generate clean explanation
        details = generate_explanation(input_df, prediction, probability)
        details = [str(d) for d in details]  # Force plain strings
        
        # Generate clean similar patterns
        similar_patterns = generate_similar_patterns(attack_type)
        for pattern in similar_patterns:
            pattern['attack_type'] = str(pattern.get('attack_type', ''))
            pattern['protocol'] = str(pattern.get('protocol', ''))
            pattern['service'] = str(pattern.get('service', ''))
            pattern['similarity'] = float(pattern.get('similarity', 0.0))
        
        # Class probabilities
        class_probabilities = {
            'labels': ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'],
            'values': [
                probability[0],
                probability[1] * 0.7 if attack_type == "DoS (Denial of Service)" else 0.01,
                probability[1] * 0.7 if attack_type == "Probe Attack" else 0.01,
                probability[1] * 0.7 if attack_type == "R2L (Remote to Local)" else 0.01,
                probability[1] * 0.7 if attack_type == "U2R (User to Root)" else 0.01
            ]
        }
        
        # Final clean result
        result = {
            'prediction': 'Anomaly Detected' if prediction == 1 else 'Normal Traffic',
            'probability': float(max(probability)),
            'attack_type': attack_type,
            'details': details,
            'similar_patterns': similar_patterns,
            'class_probabilities': class_probabilities
        }
        
        return render_template('results.html', result=result)
    
    except Exception as e:
        flash(f"Error making prediction: {str(e)}", "danger")
        return redirect(url_for('predict_form'))

# @app.route('/predict', methods=['POST'])
# def predict():
#     try:
#         # Check if model is loaded
#         if not load_model_components():
#             return redirect(url_for('predict_form'))
        
#         # Get form data
#         input_data = {}
#         for col in FEATURE_NAMES:
#             if col in request.form:
#                 input_data[col] = request.form[col]
#             else:
#                 # Default values for missing fields
#                 input_data[col] = '0'
        
#         # Convert to DataFrame
#         input_df = pd.DataFrame([input_data])
        
#         # Preprocess the input data
#         processed_data = preprocess_input(input_df)
        
#         # Make prediction
#         prediction = model.predict(processed_data)[0]
#         probability = model.predict_proba(processed_data)[0]
        
#         # Convert numpy types to Python native types
#         prediction = convert_numpy_types(prediction)
#         probability = [convert_numpy_types(p) for p in probability]
        
#         # Get attack type prediction
#         attack_type = "Unknown"
#         if prediction == 1:
#             # This is a simplified approach - in a real system you'd use a multi-class model
#             # or additional logic to determine the specific attack type
#             if float(input_data.get('serrorrate', 0)) > 0.5:
#                 attack_type = "DoS (Denial of Service)"
#             elif float(input_data.get('dsthostcount', 0)) > 200:
#                 attack_type = "Probe Attack"
#             elif float(input_data.get('numfailedlogins', 0)) > 0:
#                 attack_type = "R2L (Remote to Local)"
#             elif float(input_data.get('rootshell', 0)) > 0:
#                 attack_type = "U2R (User to Root)"
#             else:
#                 attack_type = "Network Anomaly"
        
#         # Generate explanation details
#         details = generate_explanation(input_df, prediction, probability)
        
#         # Generate similar patterns
#         similar_patterns = generate_similar_patterns(attack_type)
        
#         # Create class probabilities for visualization
#         class_probabilities = {
#             'labels': ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'],
#             'values': [probability[0], 
#                       probability[1] * 0.7 if attack_type == "DoS (Denial of Service)" else 0.01,
#                       probability[1] * 0.7 if attack_type == "Probe Attack" else 0.01,
#                       probability[1] * 0.7 if attack_type == "R2L (Remote to Local)" else 0.01,
#                       probability[1] * 0.7 if attack_type == "U2R (User to Root)" else 0.01]
#         }
        
#         result = {
#             'prediction': 'Anomaly Detected' if prediction == 1 else 'Normal Traffic',
#             'probability': float(max(probability)),
#             'attack_type': attack_type,
#             'details': details,
#             'similar_patterns': similar_patterns,
#             'class_probabilities': class_probabilities
#         }
        
#         return render_template('results.html', result=result)
    
#     except Exception as e:
#         flash(f"Error making prediction: {str(e)}", "danger")
#         return redirect(url_for('predict_form'))

# API endpoint for timeline data
@app.route('/api/timeline-data')
def timeline_data():
    timeframe = request.args.get('timeframe', 'daily')
    
    # Generate mock timeline data based on timeframe
    if timeframe == 'daily':
        labels = [(datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7, 0, -1)]
        dos = [np.random.randint(5, 30) for _ in range(7)]
        probe = [np.random.randint(3, 15) for _ in range(7)]
        r2l = [np.random.randint(0, 8) for _ in range(7)]
        u2r = [np.random.randint(0, 3) for _ in range(7)]
    elif timeframe == 'weekly':
        labels = [(datetime.now() - timedelta(weeks=i)).strftime('%Y-%m-%d') for i in range(8, 0, -1)]
        dos = [np.random.randint(20, 100) for _ in range(8)]
        probe = [np.random.randint(10, 50) for _ in range(8)]
        r2l = [np.random.randint(5, 20) for _ in range(8)]
        u2r = [np.random.randint(1, 10) for _ in range(8)]
    else:  # monthly
        labels = [(datetime.now() - timedelta(days=i*30)).strftime('%Y-%m') for i in range(6, 0, -1)]
        dos = [np.random.randint(100, 400) for _ in range(6)]
        probe = [np.random.randint(50, 200) for _ in range(6)]
        r2l = [np.random.randint(20, 80) for _ in range(6)]
        u2r = [np.random.randint(5, 30) for _ in range(6)]
    
    return jsonify({
        'labels': labels,
        'dos': dos,
        'probe': probe,
        'r2l': r2l,
        'u2r': u2r
    })

# Help route
@app.route('/help')
def help_page():
    # Get feature descriptions
    feature_descriptions = get_feature_descriptions()
    
    # Get attack type descriptions
    attack_descriptions = {
        'DoS (Denial of Service)': 'Attacks that attempt to make a machine or network resource unavailable to its intended users.',
        'Probe Attack': 'Surveillance and other probing attacks, like port scanning.',
        'R2L (Remote to Local)': 'Unauthorized access from a remote machine to a local machine.',
        'U2R (User to Root)': 'Unauthorized access to local superuser (root) privileges.',
        'Normal': 'Regular network traffic with no malicious intent.'
    }
    
    return render_template('help.html', 
                          feature_descriptions=feature_descriptions,
                          attack_descriptions=attack_descriptions)

def preprocess_input(input_df):
    """Preprocess input data for prediction"""
    # Convert data types
    for col in input_df.columns:
        if col not in ['protocoltype', 'service', 'flag']:
            input_df[col] = input_df[col].astype(float)
    
    # Encode categorical features
    for col in input_df.select_dtypes(include=['object']).columns:
        if col in encoder_dict:
            try:
                input_df[col] = encoder_dict[col].transform(input_df[col])
            except ValueError:
                # Handle unknown categories
                input_df[col] = 0
    
    # Scale numerical features
    return scaler.transform(input_df)

def generate_dashboard_visualizations(train_data, test_data):
    """Generate visualizations for dashboard"""
    visualizations = {}
    
    # 1. Attack Distribution Pie Chart
    attack_counts = train_data['attack'].value_counts()
    fig = px.pie(
        names=attack_counts.index,
        values=attack_counts.values,
        title='Distribution of Attack Types',
        color_discrete_sequence=px.colors.qualitative.Bold
    )
    visualizations['attack_distribution'] = fig.to_json()
    
    # 2. Protocol Distribution by Attack Status
    protocol_data = pd.crosstab(train_data['protocoltype'], train_data['binary_attack'])
    protocol_data.columns = ['Normal', 'Attack']
    fig = px.bar(
        protocol_data, 
        barmode='group',
        title='Protocol Distribution by Attack Status',
        labels={'value': 'Count', 'variable': 'Traffic Type'},
        color_discrete_sequence=['#1cc88a', '#e74a3b']
    )
    visualizations['protocol_distribution'] = fig.to_json()
    
    # 3. Feature Importance (if available)
    if hasattr(model, 'feature_importances_'):
        feature_importance = pd.DataFrame({
            'Feature': FEATURE_NAMES,
            'Importance': model.feature_importances_
        }).sort_values('Importance', ascending=False).head(15)
        
        fig = px.bar(
            feature_importance, 
            x='Importance',
            y='Feature',
            title='Top 15 Feature Importance',
            orientation='h',
            color='Importance',
            color_continuous_scale='Viridis'
        )
        visualizations['feature_importance'] = fig.to_json()
    
    # 4. Correlation Heatmap
    # numeric_cols = ['duration', 'srcbytes', 'dstbytes', 'count', 'serrorrate', 'rerrorrate', 'samesrvrate', 'dsthostcount']
    # corr_matrix = train_data[numeric_cols].corr().round(2)
    
    # fig = px.imshow(
    #     corr_matrix,
    #     text_auto=True,
    #     title='Feature Correlation Heatmap',
    #     color_continuous_scale='RdBu_r',
    #     aspect="auto"
    # )
    # visualizations['correlation_heatmap'] = fig.to_json()
    
    return visualizations

def generate_detailed_visualizations(data):
    """Generate additional detailed visualizations"""
    visualizations = {}
    
    # 1. Source Bytes Distribution by Attack Type
    fig = px.box(
        data, 
        x='attack', 
        y='srcbytes',
        title='Source Bytes Distribution by Attack Type',
        color='attack',
        log_y=True  # Log scale for better visualization
    )
    visualizations['srcbytes_distribution'] = fig.to_json()
    
    # 2. Destination Bytes Distribution by Attack Type
    fig = px.box(
        data, 
        x='attack', 
        y='dstbytes',
        title='Destination Bytes Distribution by Attack Type',
        color='attack',
        log_y=True  # Log scale for better visualization
    )
    visualizations['dstbytes_distribution'] = fig.to_json()
    
    # 3. Error Rate Comparison
    error_cols = ['serrorrate', 'rerrorrate', 'srvserrorrate', 'srvrerrorrate', 
                 'dsthostserrorrate', 'dsthostrerrorrate']
    
    error_data = data.groupby('binary_attack')[error_cols].mean().reset_index()
    error_data_melted = pd.melt(error_data, id_vars=['binary_attack'], value_vars=error_cols)
    error_data_melted['binary_attack'] = error_data_melted['binary_attack'].map({0: 'Normal', 1: 'Attack'})
    
    fig = px.bar(
        error_data_melted,
        x='variable',
        y='value',
        color='binary_attack',
        barmode='group',
        title='Error Rates Comparison: Normal vs Attack Traffic',
        labels={'variable': 'Error Rate Type', 'value': 'Average Rate', 'binary_attack': 'Traffic Type'}
    )
    visualizations['error_rates'] = fig.to_json()
    
    # 4. Service Distribution for Top 10 Services
    service_counts = data['service'].value_counts().head(10)
    fig = px.bar(
        x=service_counts.index,
        y=service_counts.values,
        title='Top 10 Services in Network Traffic',
        labels={'x': 'Service', 'y': 'Count'}
    )
    visualizations['service_distribution'] = fig.to_json()
    
    # 5. 3D Scatter Plot of Key Features
    fig = px.scatter_3d(
        data.sample(1000),  # Sample for better performance
        x='count',
        y='serrorrate',
        z='dsthostcount',
        color='binary_attack',
        color_discrete_map={0: '#1cc88a', 1: '#e74a3b'},
        title='3D Visualization of Key Features',
        labels={'binary_attack': 'Attack Status', 'count': 'Connection Count', 
                'serrorrate': 'SYN Error Rate', 'dsthostcount': 'Destination Host Count'}
    )
    visualizations['scatter_3d'] = fig.to_json()
    
    return visualizations

def generate_recent_anomalies(n=10):
    """Generate mock recent anomalies for dashboard"""
    anomalies = []
    attack_types = ['neptune', 'smurf', 'portsweep', 'satan', 'guess_passwd', 'buffer_overflow']
    protocols = ['tcp', 'udp', 'icmp']
    services = ['http', 'private', 'domain_u', 'smtp', 'ftp_data', 'telnet']
    
    now = datetime.now()
    
    for i in range(n):
        anomaly = {
            'id': i + 1,
            'time': (now - timedelta(minutes=i*5)).strftime('%Y-%m-%d %H:%M:%S'),
            'protocol': np.random.choice(protocols),
            'service': np.random.choice(services),
            'attack_type': np.random.choice(attack_types),
            'src_bytes': np.random.randint(0, 10000),
            'dst_bytes': np.random.randint(0, 10000),
            'confidence': np.random.randint(70, 99)
        }
        anomalies.append(anomaly)
    
    return anomalies

def get_example_data():
    """Get example data for normal and attack cases"""
    normal_example = {
        'duration': 0,
        'protocoltype': 'tcp',
        'service': 'http',
        'flag': 'SF',
        'srcbytes': 215,
        'dstbytes': 45076,
        'land': 0,
        'wrongfragment': 0,
        'urgent': 0,
        'hot': 0,
        'numfailedlogins': 0,
        'loggedin': 1,
        'numcompromised': 0,
        'rootshell': 0,
        'suattempted': 0,
        'numroot': 0,
        'numfilecreations': 0,
        'numshells': 0,
        'numaccessfiles': 0,
        'numoutboundcmds': 0,
        'ishostlogin': 0,
        'isguestlogin': 0,
        'count': 1,
        'srvcount': 1,
        'serrorrate': 0,
        'srvserrorrate': 0,
        'rerrorrate': 0,
        'srvrerrorrate': 0,
        'samesrvrate': 1,
        'diffsrvrate': 0,
        'srvdiffhostrate': 0,
        'dsthostcount': 255,
        'dsthostsrvcount': 255,
        'dsthostsamesrvrate': 1,
        'dsthostdiffsrvrate': 0,
        'dsthostsamesrcportrate': 0.01,
        'dsthostsrvdiffhostrate': 0.03,
        'dsthostserrorrate': 0,
        'dsthostsrvserrorrate': 0,
        'dsthostrerrorrate': 0,
        'dsthostsrvrerrorrate': 0
    }
    
    attack_example = {
        'duration': 0,
        'protocoltype': 'tcp',
        'service': 'private',
        'flag': 'S0',
        'srcbytes': 0,
        'dstbytes': 0,
        'land': 0,
        'wrongfragment': 0,
        'urgent': 0,
        'hot': 0,
        'numfailedlogins': 0,
        'loggedin': 0,
        'numcompromised': 0,
        'rootshell': 0,
        'suattempted': 0,
        'numroot': 0,
        'numfilecreations': 0,
        'numshells': 0,
        'numaccessfiles': 0,
        'numoutboundcmds': 0,
        'ishostlogin': 0,
        'isguestlogin': 0,
        'count': 123,
        'srvcount': 123,
        'serrorrate': 1,
        'srvserrorrate': 1,
        'rerrorrate': 0,
        'srvrerrorrate': 0,
        'samesrvrate': 1,
        'diffsrvrate': 0,
        'srvdiffhostrate': 0,
        'dsthostcount': 255,
        'dsthostsrvcount': 20,
        'dsthostsamesrvrate': 0.08,
        'dsthostdiffsrvrate': 0.07,
        'dsthostsamesrcportrate': 0,
        'dsthostsrvdiffhostrate': 0,
        'dsthostserrorrate': 1,
        'dsthostsrvserrorrate': 1,
        'dsthostrerrorrate': 0,
        'dsthostsrvrerrorrate': 0
    }
    
    return normal_example, attack_example

def get_feature_descriptions():
    """Get descriptions for each feature"""
    return {
        'duration': 'Length of the connection in seconds',
        'protocoltype': 'Type of protocol (tcp, udp, icmp)',
        'service': 'Network service on destination (http, ftp, telnet, etc.)',
        'flag': 'Status of the connection (SF: normal, S0: connection attempt, REJ: rejected)',
        'srcbytes': 'Number of data bytes sent from source to destination',
        'dstbytes': 'Number of data bytes sent from destination to source',
        'land': '1 if connection is from/to same host/port; 0 otherwise',
        'wrongfragment': 'Number of wrong fragments',
        'urgent': 'Number of urgent packets',
        'hot': 'Number of "hot" indicators (suspicious activities)',
        'numfailedlogins': 'Number of failed login attempts',
        'loggedin': '1 if successfully logged in; 0 otherwise',
        'numcompromised': 'Number of compromised conditions',
        'rootshell': '1 if root shell is obtained; 0 otherwise',
        'suattempted': '1 if "su root" command attempted; 0 otherwise',
        'numroot': 'Number of root accesses',
        'numfilecreations': 'Number of file creation operations',
        'numshells': 'Number of shell prompts',
        'numaccessfiles': 'Number of operations on access control files',
        'numoutboundcmds': 'Number of outbound commands in an ftp session',
        'ishostlogin': '1 if the login belongs to the "hot" list; 0 otherwise',
        'isguestlogin': '1 if the login is a guest login; 0 otherwise',
        'count': 'Number of connections to the same host in the past 2 seconds',
        'srvcount': 'Number of connections to the same service in the past 2 seconds',
        'serrorrate': '% of connections that have SYN errors',
        'srvserrorrate': '% of connections to the same service that have SYN errors',
        'rerrorrate': '% of connections that have REJ errors',
        'srvrerrorrate': '% of connections to the same service that have REJ errors',
        'samesrvrate': '% of connections to the same service',
        'diffsrvrate': '% of connections to different services',
        'srvdiffhostrate': '% of connections to different hosts',
        'dsthostcount': 'Number of connections to the same destination host',
        'dsthostsrvcount': 'Number of connections to the same destination host using same service',
        'dsthostsamesrvrate': '% of connections to the same destination host using same service',
        'dsthostdiffsrvrate': '% of connections to the same destination host using different services',
        'dsthostsamesrcportrate': '% of connections to the same destination host using same source port',
        'dsthostsrvdiffhostrate': '% of connections to the same destination host using same service coming from different hosts',
        'dsthostserrorrate': '% of connections to the same destination host that have SYN errors',
        'dsthostsrvserrorrate': '% of connections to the same destination host and service that have SYN errors',
        'dsthostrerrorrate': '% of connections to the same destination host that have REJ errors',
        'dsthostsrvrerrorrate': '% of connections to the same destination host and service that have REJ errors'
    }

def generate_explanation(input_data, prediction, probability):
    """Generate detailed explanation for the prediction"""
    details = []
    
    if prediction == 1:  # Anomaly detected
        # Check for high error rates
        if float(input_data['serrorrate'].values[0]) > 0.5:
            details.append("High SYN error rate detected ({}%), which is typical of SYN flood attacks.".format(
                float(input_data['serrorrate'].values[0]) * 100))
        
        if float(input_data['rerrorrate'].values[0]) > 0.5:
            details.append("High REJ error rate detected ({}%), indicating possible port scanning activity.".format(
                float(input_data['rerrorrate'].values[0]) * 100))
        
        # Check for unusual connection counts
        if float(input_data['count'].values[0]) > 100:
            details.append("Unusually high number of connections ({}) to the same host in a short time period.".format(
                int(input_data['count'].values[0])))
        
        # Check for unusual bytes transferred
        if float(input_data['srcbytes'].values[0]) > 10000:
            details.append("Large amount of data ({} bytes) sent from source, potential data exfiltration.".format(
                int(input_data['srcbytes'].values[0])))
        
        if float(input_data['dstbytes'].values[0]) > 10000:
            details.append("Large amount of data ({} bytes) received from destination.".format(
                int(input_data['dstbytes'].values[0])))
        
        # Check for root access attempts
        if float(input_data['rootshell'].values[0]) > 0:
            details.append("Root shell was obtained, indicating a successful privilege escalation attack.")
        
        if float(input_data['numfailedlogins'].values[0]) > 0:
            details.append("Failed login attempts detected, possible brute force attack.")
        
        # If no specific indicators found
        if not details:
            details.append("Multiple subtle indicators suggest anomalous behavior.")
            details.append("The combination of connection parameters doesn't match normal traffic patterns.")
    else:  # Normal traffic
        details.append("Connection parameters are consistent with legitimate network traffic.")
        details.append("No suspicious indicators were detected in this traffic pattern.")
        
        if input_data['service'].values[0] == 'http' and input_data['flag'].values[0] == 'SF':
            details.append("This appears to be normal HTTP traffic with a successfully established connection.")
        
        if float(input_data['loggedin'].values[0]) > 0:
            details.append("Successful login activity with no suspicious behavior.")
    
    # Add confidence information
    confidence = max(probability) * 100
    if confidence > 90:
        details.append("The model has high confidence ({:.1f}%) in this classification.".format(confidence))
    elif confidence > 70:
        details.append("The model has moderate confidence ({:.1f}%) in this classification.".format(confidence))
    else:
        details.append("The model has lower confidence ({:.1f}%) in this classification. Consider additional verification.".format(confidence))
    
    return details

def generate_similar_patterns(attack_type):
    """Generate similar attack patterns for context"""
    patterns = []
    
    if attack_type == "DoS (Denial of Service)":
        patterns.append({
            'attack_type': 'Neptune (SYN Flood)',
            'protocol': 'TCP',
            'service': 'Various',
            'similarity': 0.92
        })
        patterns.append({
            'attack_type': 'Smurf',
            'protocol': 'ICMP',
            'service': 'ecr_i',
            'similarity': 0.85
        })
        patterns.append({
            'attack_type': 'Pod (Ping of Death)',
            'protocol': 'ICMP',
            'service': 'eco_i',
            'similarity': 0.78
        })
    elif attack_type == "Probe Attack":
        patterns.append({
            'attack_type': 'Portsweep',
            'protocol': 'TCP',
            'service': 'Various',
            'similarity': 0.88
        })
        patterns.append({
            'attack_type': 'IPSweep',
            'protocol': 'ICMP',
            'service': 'eco_i',
            'similarity': 0.82
        })
        patterns.append({
            'attack_type': 'Nmap',
            'protocol': 'TCP',
            'service': 'Various',
            'similarity': 0.75
        })
    elif attack_type == "R2L (Remote to Local)":
        patterns.append({
            'attack_type': 'Guess Password',
            'protocol': 'TCP',
            'service': 'ftp/telnet/pop_3',
            'similarity': 0.90
        })
        patterns.append({
            'attack_type': 'Warezmaster',
            'protocol': 'TCP',
            'service': 'ftp',
            'similarity': 0.81
        })
        patterns.append({
            'attack_type': 'Phf',
            'protocol': 'TCP',
            'service': 'http',
            'similarity': 0.73
        })
    elif attack_type == "U2R (User to Root)":
        patterns.append({
            'attack_type': 'Buffer Overflow',
            'protocol': 'TCP',
            'service': 'Various',
            'similarity': 0.89
        })
        patterns.append({
            'attack_type': 'Rootkit',
            'protocol': 'TCP',
            'service': 'telnet/ftp',
            'similarity': 0.84
        })
        patterns.append({
            'attack_type': 'Loadmodule',
            'protocol': 'TCP',
            'service': 'Various',
            'similarity': 0.77
        })
    else:  # Normal or unknown
        patterns.append({
            'attack_type': 'Normal HTTP Traffic',
            'protocol': 'TCP',
            'service': 'http',
            'similarity': 0.95
        })
        patterns.append({
            'attack_type': 'Normal FTP Traffic',
            'protocol': 'TCP',
            'service': 'ftp',
            'similarity': 0.88
        })
        patterns.append({
            'attack_type': 'Normal DNS Traffic',
            'protocol': 'UDP',
            'service': 'domain_u',
            'similarity': 0.82
        })
    
    return patterns

if __name__ == '__main__':
    app.run(debug=True)
