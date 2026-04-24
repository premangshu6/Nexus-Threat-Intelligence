# Nexus: Threat Intelligence Platform
### Practical 15 — LLM-Based Application Development

---

## 1. Overview

**Project Title:** Nexus — AI-Powered Network Intrusion Detection System  
**Practical Objective:** Use any LLM to build a small, functional project  
**LLM Used:** Antigravity (powered by Google DeepMind)  
**Developed By:** [Your Name / Roll Number]  
**Date:** April 2026

---

## 2. Project Idea & Motivation

Network security is one of the most critical challenges in modern computing. As organizations grow increasingly dependent on internet-connected infrastructure, the volume and sophistication of cyberattacks have scaled dramatically. Traditional rule-based intrusion detection systems (IDS) rely on predefined patterns and signatures — a method that fundamentally fails against novel, zero-day attacks.

The idea behind **Nexus** was to build a modern, AI-powered Intrusion Detection System (IDS) that goes beyond static rules by:

- Leveraging **supervised machine learning** to classify network traffic as known attack types.
- Leveraging **unsupervised anomaly detection** to flag unusual traffic that may represent new, unseen threats.
- Presenting all intelligence through a **premium, live dashboard** that makes complex security data accessible, beautiful, and actionable.

The project was conceived, architected, developed, and refined entirely through a conversation with **Antigravity**, a state-of-the-art agentic AI coding assistant. The student's role was to define the goals, review the output, and iteratively direct the LLM to improve the product through a structured dialogue — precisely as described in the practical objective.

---

## 3. Role of the LLM (Antigravity)

Antigravity was used at every single stage of this project:

| Stage | What Antigravity Did |
|---|---|
| **Ideation** | Proposed using the NSL-KDD dataset, suggested the dual-model approach (RF + Isolation Forest) |
| **Data Pipeline** | Wrote the full `train_model.py` script including encoding, train/test split, and evaluation |
| **Model Training** | Configured both ML models with appropriate hyperparameters, generated evaluation metrics |
| **Application** | Built the entire `app.py` Streamlit application from scratch |
| **UI Design** | Iteratively improved the UI with glassmorphism, live CSS animations, dark mode, gradient titles |
| **Feature Addition** | Added the Attack Diagnostics section, Global Threat Map, Telemetry Sidebar, and Export feature |
| **Debugging** | Diagnosed and fixed issues with video backgrounds, external URL failures, CSS rendering |
| **Documentation** | Wrote this document |

The development process was entirely conversational. The student issued high-level instructions (e.g., *"make the background live"*, *"add attack information"*) and Antigravity translated them into production-ready code, explained its decisions, and requested review where necessary.

---

## 4. Dataset — NSL-KDD

The **NSL-KDD dataset** is the standard benchmark dataset for network intrusion detection research. It is an improved version of the original KDD Cup 1999 dataset, addressing several key flaws such as redundant records and class imbalance.

### Dataset File Used
- `KDDTrain+.txt` — the full training set

### Features (41 total)

The dataset contains **41 features** categorized into four groups:

| Category | Examples |
|---|---|
| **Basic TCP/IP features** | `duration`, `protocol_type`, `service`, `flag`, `src_bytes`, `dst_bytes` |
| **Content features** | `hot`, `num_failed_logins`, `logged_in`, `num_compromised`, `root_shell` |
| **Traffic features** | `count`, `srv_count`, `serror_rate`, `rerror_rate`, `same_srv_rate` |
| **Host-based features** | `dst_host_count`, `dst_host_srv_count`, `dst_host_same_srv_rate` |

### Categorical Features
Three columns are non-numeric and were encoded:
- `protocol_type` — TCP, UDP, ICMP
- `service` — http, ftp, telnet, private, etc.
- `flag` — SF, S0, S1, REJ, etc.

### Attack Categories
The dataset contains traffic labeled as either **normal** or one of these attack categories:

| Category | Description | Examples |
|---|---|---|
| **DoS** | Denial of Service — overwhelm the target | neptune, smurf, teardrop, pod |
| **Probe** | Surveillance/scanning attacks | satan, ipsweep, portsweep, nmap |
| **R2L** | Remote to Local — gain unauthorized access | guess_passwd, ftp_write |
| **U2R** | User to Root — privilege escalation | buffer_overflow, rootkit |

---

## 5. Machine Learning Models

The system uses a **dual-model architecture**: one supervised classifier and one unsupervised anomaly detector, running in parallel.

---

### 5.1 Model 1 — Random Forest Classifier

**Purpose:** Classify each network connection as `normal` or as a specific named attack type (e.g., neptune, smurf, satan).

**Why Random Forest?**
- Handles high-dimensional tabular data exceptionally well
- Robust to outliers and irrelevant features
- Provides built-in **feature importance** scores
- Highly interpretable and well-suited for security contexts where explainability matters

**Configuration:**

```python
RandomForestClassifier(
    n_estimators=150,   # 150 decision trees in the ensemble
    random_state=42,    # For reproducibility
    n_jobs=-1           # Use all CPU cores for parallel training
)
```

**How It Works:**
- 150 individual decision trees are trained on random subsets of the data.
- Each tree independently votes on the class label.
- The final prediction is determined by a **majority vote** across all trees.
- This ensemble approach dramatically reduces overfitting compared to a single decision tree.

**Training:**
```python
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
rf_model.fit(X_train, y_train)
```

An 80/20 train-test split is used. The model is trained on 80% of the data and evaluated on the remaining 20%.

**Evaluation Metrics:**
- **Accuracy** — Overall percentage of correctly classified connections
- **Precision (weighted)** — Of all connections flagged as a given attack, how many actually were
- **Recall (weighted)** — Of all actual attacks, what percentage did the model correctly catch
- **F1 Score (weighted)** — The harmonic mean of precision and recall

---

### 5.2 Model 2 — Isolation Forest (Anomaly Detection)

**Purpose:** Identify connections that statistically deviate from normal behavior, regardless of whether they match a known attack signature. This is the system's defense against **zero-day and novel threats**.

**Why Isolation Forest?**
- It is an **unsupervised** algorithm — it does not require labeled attack data.
- It works by randomly partitioning the feature space and measuring how quickly a data point can be isolated.
- Anomalous points (outliers) are isolated in far fewer partitions than normal points.
- It scales extremely well to high-dimensional data like network traffic.

**Configuration:**

```python
IsolationForest(
    contamination=0.05,  # Assumes 5% of training data are anomalies
    random_state=42
)
```

**How It Works:**
1. The algorithm builds an ensemble of random isolation trees.
2. For each data point, it counts how many splits are needed to isolate it.
3. Points that require fewer splits receive a **lower anomaly score**.
4. Points with scores below the threshold (determined by `contamination=0.05`) are flagged as **Anomaly**.

**Output:**
- `1` → Normal traffic
- `-1` → Anomaly (suspicious connection)

---

## 6. Training Pipeline (`train_model.py`)

The entire data processing and model training flow is encapsulated in `train_model.py`. Here is a step-by-step breakdown:

```
1. Load Dataset
   └── Read KDDTrain+.txt with 43 named columns (41 features + label + difficulty)

2. Encode Categorical Features
   └── Apply LabelEncoder to: protocol_type, service, flag
   └── Store encoders in cat_encoders.pkl for use in the app

3. Encode Attack Labels
   └── Apply LabelEncoder to the 'label' column
   └── Store encoder in label_encoder.pkl

4. Feature/Target Split
   └── X = all 41 feature columns
   └── y = encoded label column

5. Train/Test Split (80/20)

6. Train Random Forest Classifier
   └── 150 estimators, all CPU cores, random_state=42

7. Evaluate on Test Set
   └── Compute Accuracy, Precision, Recall, F1, Confusion Matrix

8. Generate Feature Importance Chart
   └── Saved as feature_importance.png

9. Train Isolation Forest
   └── contamination=0.05, random_state=42

10. Save All Artifacts
    └── model.pkl           — Random Forest model
    └── iso_model.pkl       — Isolation Forest model
    └── label_encoder.pkl   — Attack label encoder
    └── cat_encoders.pkl    — Categorical feature encoders
```

---

## 7. Application (`app.py`)

The front-end application is built using **Streamlit**, a Python-native web framework designed for data science dashboards. It is structured as a single-page application with several distinct sections.

### 7.1 Live Cyberspace Background

The background is built entirely with **CSS animations** — two layered effects:

1. **Scrolling Starfield** (`.stApp::before`) — A repeating radial gradient pattern of colored data nodes (blue, purple, white) that continuously scrolls upward, simulating streaming data.
2. **3D Scanning Grid** (`.stApp::after`) — A perspective-transformed grid that scrolls to create the illusion of moving forward through cyberspace.

This approach was chosen over video embeds for reliability, performance, and zero dependency on external URLs.

### 7.2 Glassmorphism UI

All containers use **glassmorphism** — a modern design pattern combining:
- Semi-transparent dark backgrounds (`rgba(15, 20, 30, 0.55)`)
- High-blur backdrop filters (`blur(20px) saturate(200%)`)
- Subtle border highlights (`rgba(255, 255, 255, 0.1)`)
- Deep box shadows

### 7.3 Live Telemetry Sidebar

The sidebar displays simulated server health metrics (CPU Load, Memory Usage, Network Throughput) with animated progress bars. These values are pseudo-randomized on each app load to simulate a live monitoring environment.

### 7.4 Core Analysis Pipeline (on CSV upload)

```
Upload CSV → Encode Categorical Columns
          → Run Isolation Forest → tag each row as Normal/Anomaly
          → Run Random Forest   → classify each row by attack type
          → Compute Threat Score (0 for normal, 90 for attack)
          → Display Metrics (Total, Attacks, Anomalies)
          → Threat Diagnostics (per attack type)
          → Global Threat Map
          → Distribution Charts
          → Export Report
```

### 7.5 Threat Diagnostics

For each unique attack type detected in the upload, the system renders a detailed expandable panel showing:
- **Classification Type** (e.g., DoS — SYN Flood)
- **Key NSL-KDD Parameters** that suggest that specific attack
- **Recommended Mitigation/Fix** strategies

This intelligence is sourced from the built-in `ATTACK_INFO` knowledge base — a curated dictionary of the most common NSL-KDD attack profiles.

### 7.6 Global Threat Map

Since raw network traffic does not include geographic data, the system uses **simulated geographic coordinates** seeded from real-world internet hotspots (North America, Europe, Asia) to visually demonstrate the concept of global threat origin mapping. This feature illustrates how an enterprise-grade system would visualize attack origins in production.

### 7.7 Interactive Charts (Plotly Express)

Two Plotly charts are rendered side-by-side:

| Chart | Type | Purpose |
|---|---|---|
| Overall Traffic Status | Donut Pie Chart | Normal vs. Attack split |
| Frequency of Specific Threats | Colored Bar Chart | Which attack types appeared, and how often |

Both charts use transparent backgrounds and light-colored fonts to blend seamlessly with the dark theme.

### 7.8 Export Intelligence Report

A one-click download button exports the fully enriched dataset (original features + `Anomaly Detection` + `Prediction` + `Threat Score`) as a CSV file named `nexus_threat_report.csv`.

---

## 8. Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python 3 |
| ML Framework | scikit-learn |
| Data Handling | pandas, numpy |
| Model Persistence | joblib |
| Web Application | Streamlit |
| Visualization | Plotly Express |
| UI Styling | Custom CSS (Glassmorphism, CSS Animations) |
| Development Assistant | Antigravity (LLM by Google DeepMind) |

---

## 9. Files & Directory Structure

```
nexus-threat-intelligence/
│
├── app.py              # Main Streamlit application (UI + inference)
├── train_model.py      # Data pipeline and model training script
├── KDDTrain+.txt       # NSL-KDD training dataset (raw)
├── test_sample.csv     # Sample CSV for demonstration (10 connections)
│
├── model.pkl           # Trained Random Forest Classifier
├── iso_model.pkl       # Trained Isolation Forest
├── label_encoder.pkl   # Attack label encoder
├── cat_encoders.pkl    # Categorical feature encoders
│
└── feature_importance.png  # Bar chart of feature importance scores
```

---

## 10. Results on `test_sample.csv`

The provided test sample contains **10 network connections** with the following characteristics:

| # | Duration | Protocol | Flag | src_bytes | Detected As |
|---|---|---|---|---|---|
| 1–5 | 0 | tcp | S0 | 0 | neptune (DoS — SYN Flood) |
| 6 | 2 | udp | SF | 4000 | Varies |
| 7–9 | 3–5 | tcp | S0 | 4500–5000 | neptune (DoS — SYN Flood) |
| 10 | 6 | udp | SF | 3500 | Varies |

**Key observations by the model:**
- The `S0` flag (SYN sent, no reply) combined with zero `dst_bytes` and high `serror_rate`/`count` are the strongest indicators of a **SYN Flood (neptune) attack**.
- The model correctly identifies these patterns without being explicitly told the attack label.

---

## 11. Conclusion

Nexus demonstrates that a fully functional, visually polished, AI-powered security tool can be developed rapidly using an LLM assistant. The project achieves:

- **Dual-layer threat detection** using both supervised and unsupervised ML
- **Explainable AI outputs** via the Threat Diagnostics knowledge base
- **A premium, production-quality UI** with live animations, glassmorphism, and interactive Plotly visualizations
- **Practical utility** — the CSV upload, threat map, and export features make it immediately usable

The use of **Antigravity** as the LLM co-pilot dramatically accelerated development. Every component — from the data encoding pipeline to the animated CSS background — was produced through high-level natural language instructions, reviewed by the student, and refined iteratively. This demonstrates precisely the kind of **LLM-augmented development workflow** that is becoming standard in modern software engineering.
