import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# NSL-KDD column names
columns = [
'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
'root_shell','su_attempted','num_root','num_file_creations','num_shells',
'num_access_files','num_outbound_cmds','is_host_login','is_guest_login',
'count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate',
'label','difficulty'
]

print("Loading dataset...")
df = pd.read_csv("KDDTrain+.txt", names=columns)

print("Dataset shape:", df.shape)

# Encode categorical columns
cat_cols = ['protocol_type','service','flag']
cat_encoders = {}

for col in cat_cols:
    encoder = LabelEncoder()
    df[col] = encoder.fit_transform(df[col])
    cat_encoders[col] = encoder

# Encode attack labels
label_encoder = LabelEncoder()
df['label'] = label_encoder.fit_transform(df['label'])

# Feature / target split
X = df.drop(['label','difficulty'], axis=1)
y = df['label']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("\nTraining Random Forest classifier...")

rf_model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1
)

rf_model.fit(X_train, y_train)

# Predictions
y_pred = rf_model.predict(X_test)

# Evaluation metrics
print("\nModel Evaluation")
print("----------------")

print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred, average='weighted'))
print("Recall:", recall_score(y_test, y_pred, average='weighted'))
print("F1 Score:", f1_score(y_test, y_pred, average='weighted'))

print("\nConfusion Matrix")
print(confusion_matrix(y_test, y_pred))

# Feature importance visualization
importances = rf_model.feature_importances_
features = X.columns

importance_df = pd.DataFrame({
    "feature": features,
    "importance": importances
}).sort_values(by="importance", ascending=True)

plt.figure(figsize=(10,8))
plt.barh(importance_df["feature"], importance_df["importance"])
plt.title("Feature Importance")
plt.xlabel("Importance Score")
plt.tight_layout()
plt.savefig("feature_importance.png")

print("Feature importance chart saved as feature_importance.png")

# Train anomaly detection model
print("\nTraining Isolation Forest for anomaly detection...")

iso_model = IsolationForest(
    contamination=0.05,
    random_state=42
)

iso_model.fit(X_train)

# Sample anomaly predictions
anomaly_sample = iso_model.predict(X_test[:10])

print("\nIsolation Forest sample predictions:")
print(anomaly_sample)

# Save models and encoders
joblib.dump(rf_model, "model.pkl")
joblib.dump(iso_model, "iso_model.pkl")
joblib.dump(label_encoder, "label_encoder.pkl")
joblib.dump(cat_encoders, "cat_encoders.pkl")

print("\nModels and encoders saved successfully.")