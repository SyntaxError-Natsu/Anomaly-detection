import os
import pickle
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Define paths
MODEL_DIR = 'models'
MODEL_PATH = os.path.join(MODEL_DIR, 'anomaly_model.pkl')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')
ENCODER_PATH = os.path.join(MODEL_DIR, 'encoder.pkl')
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

def main():
    # Create models directory if it doesn't exist
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
    
    # Load data
    print("Loading data...")
    train_data = pd.read_csv(TRAIN_DATA_PATH, sep=",", names=COLUMN_NAMES)
    test_data = pd.read_csv(TEST_DATA_PATH, sep=",", names=COLUMN_NAMES)
    
    # Display basic info
    print(f"Training data shape: {train_data.shape}")
    print(f"Testing data shape: {test_data.shape}")
    
    # Check for missing values
    print("\nChecking for missing values in training data:")
    print(train_data.isnull().sum().sum())
    
    # Display class distribution
    print("\nClass distribution in training data:")
    print(train_data['attack'].value_counts())
    
    # Preprocess data
    print("\nPreprocessing data...")
    
    # Convert attack to binary (normal vs attack)
    train_data['binary_attack'] = train_data['attack'].apply(lambda x: 0 if x == 'normal' else 1)
    test_data['binary_attack'] = test_data['attack'].apply(lambda x: 0 if x == 'normal' else 1)
    
    # Handle categorical features
    encoder_dict = {}
    for col in train_data.select_dtypes(include=['object']).columns:
        if col != 'attack':  # Skip target variable
            le = LabelEncoder()
            train_data[col] = le.fit_transform(train_data[col])
            test_data[col] = le.transform(test_data[col])
            encoder_dict[col] = le
    
    # Save encoder dictionary
    with open(ENCODER_PATH, 'wb') as f:
        pickle.dump(encoder_dict, f)
    print(f"Saved encoders to {ENCODER_PATH}")
    
    # Split data
    X_train = train_data.drop(['attack', 'binary_attack', 'lastflag'], axis=1)
    y_train = train_data['binary_attack']
    X_test = test_data.drop(['attack', 'binary_attack', 'lastflag'], axis=1)
    y_test = test_data['binary_attack']
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Save scaler
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"Saved scaler to {SCALER_PATH}")
    
    # Train model
    print("\nTraining model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train_scaled, y_train)
    
    # Evaluate model
    print("\nEvaluating model...")
    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Plot confusion matrix
    plt.figure(figsize=(8, 6))
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    plt.savefig(os.path.join(MODEL_DIR, 'confusion_matrix.png'))
    
    # Plot feature importance
    if hasattr(model, 'feature_importances_'):
        feature_names = X_train.columns
        feature_importance = pd.DataFrame({
            'Feature': feature_names,
            'Importance': model.feature_importances_
        }).sort_values('Importance', ascending=False)
        
        plt.figure(figsize=(10, 8))
        sns.barplot(x='Importance', y='Feature', data=feature_importance.head(15))
        plt.title('Top 15 Feature Importance')
        plt.tight_layout()
        plt.savefig(os.path.join(MODEL_DIR, 'feature_importance.png'))
    
    # Save model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    print(f"Saved model to {MODEL_PATH}")
    
    print("\nDone! Model and utilities saved to 'models' directory.")

if __name__ == "__main__":
    main()
