import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
import time

# Page configuration
st.set_page_config(
    page_title="Nexus Threat Intelligence",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS and Live Cyberspace Background
st.markdown("""
<style>
    /* Base Transparent Setup */
    .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
        background-color: transparent !important;
        background: transparent !important;
        color: #f1f5f9;
        overflow-x: hidden;
    }
    
    /* The Deep Dark Base */
    html, body {
        background-color: #03050a !important;
    }

    /* Live Video-ish CSS Starfield & Data Nodes */
    .stApp::before {
        content: '';
        position: fixed;
        width: 200vw;
        height: 200vh;
        top: -50vh;
        left: -50vw;
        z-index: -2;
        background-image: 
            radial-gradient(2px 2px at 20px 30px, #38bdf8, rgba(0,0,0,0)),
            radial-gradient(2px 2px at 40px 70px, #8b5cf6, rgba(0,0,0,0)),
            radial-gradient(2px 2px at 50px 160px, #ffffff, rgba(0,0,0,0)),
            radial-gradient(2px 2px at 90px 40px, #38bdf8, rgba(0,0,0,0)),
            radial-gradient(2px 2px at 130px 80px, #8b5cf6, rgba(0,0,0,0)),
            radial-gradient(2px 2px at 160px 120px, #ffffff, rgba(0,0,0,0));
        background-repeat: repeat;
        background-size: 200px 200px;
        animation: starfield 40s linear infinite;
        opacity: 0.7;
    }

    /* Live 3D Scanning Grid */
    .stApp::after {
        content: '';
        position: fixed;
        top: 0; left: 0; right: 0; bottom: 0;
        z-index: -1;
        background: 
            linear-gradient(rgba(56, 189, 248, 0.15) 1px, transparent 1px),
            linear-gradient(90deg, rgba(56, 189, 248, 0.15) 1px, transparent 1px);
        background-size: 50px 50px;
        transform: perspective(600px) rotateX(60deg) scale(2.5);
        transform-origin: bottom center;
        animation: gridScan 10s linear infinite;
    }

    @keyframes starfield {
        0% { transform: translateY(0); }
        100% { transform: translateY(-1000px); }
    }
    
    @keyframes gridScan {
        0% { background-position: 0 0; }
        100% { background-position: 0 50px; }
    }

    /* Premium Glassmorphism for containers and cards */
    .css-1r6slb0, .css-1v0mbdj, div[data-testid="stSidebar"] {
        background: rgba(10, 15, 25, 0.65) !important;
        backdrop-filter: blur(20px) saturate(200%) !important;
        -webkit-backdrop-filter: blur(20px) saturate(200%) !important;
        border-right: 1px solid rgba(255, 255, 255, 0.08) !important;
    }
    
    div[data-testid="stVerticalBlock"] > div {
        background: rgba(15, 20, 30, 0.55);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 16px;
        padding: 20px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
        margin-bottom: 1rem;
    }
    
    /* Metrics styling - Neon Glow */
    [data-testid="stMetricValue"] {
        color: #38bdf8 !important;
        font-weight: 800 !important;
        font-size: 2.5rem !important;
        text-shadow: 0 0 20px rgba(56, 189, 248, 0.6);
    }
    
    /* Main Title with Gradient */
    h1 {
        background: linear-gradient(135deg, #38bdf8 0%, #8b5cf6 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
        letter-spacing: -1px;
    }
    
    /* Subheaders */
    h2, h3 {
        color: #f8fafc !important;
        font-weight: 600;
    }
    
    /* Dataframes styling */
    [data-testid="stDataFrame"] {
        background: rgba(10, 15, 25, 0.7);
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
</style>
""", unsafe_allow_html=True)

# Dictionary containing detailed attack information
ATTACK_INFO = {
    "neptune": {
        "type": "DoS (Denial of Service) - SYN Flood",
        "parameters": "High 'count' (connections to same destination), high 'serror_rate' (SYN errors), 'flag' is S0.",
        "fix": "Implement SYN cookies, rate limiting, and use firewalls to drop incomplete connections."
    },
    "smurf": {
        "type": "DoS (Denial of Service) - ICMP Echo Reply Flood",
        "parameters": "High 'src_bytes', 'protocol_type' is ICMP.",
        "fix": "Disable IP-directed broadcasts on routers. Configure hosts to not respond to ICMP requests to broadcast addresses."
    },
    "satan": {
        "type": "Probe - Port Scanning",
        "parameters": "High 'diff_srv_rate', connections to many different ports rapidly.",
        "fix": "Block scanning IP addresses, use Network Intrusion Prevention Systems (NIPS), and limit ICMP traffic."
    },
    "ipsweep": {
        "type": "Probe - Ping Sweep",
        "parameters": "ICMP protocol, connections to many different hosts ('dst_host_count' high).",
        "fix": "Block ICMP echo requests from external networks, monitor for sequential IP scanning."
    },
    "teardrop": {
        "type": "DoS - Fragmented Packets",
        "parameters": "High 'wrong_fragment' count, protocol is UDP.",
        "fix": "Ensure OS is patched against fragmentation attacks. Use firewalls to reassemble and inspect packets."
    },
    "portsweep": {
        "type": "Probe - Port Sweep",
        "parameters": "Connections to multiple services on the same host, 'dst_host_srv_count' variations.",
        "fix": "Implement rate limiting, deploy honeypots to detect scanning, block offending IPs."
    },
    "guess_passwd": {
        "type": "R2L (Root to Local) - Brute Force",
        "parameters": "High 'num_failed_logins', 'is_guest_login' might be 1.",
        "fix": "Enforce strong password policies, implement account lockout after N failed attempts, use MFA."
    }
}

DEFAULT_ATTACK = {
    "type": "Unknown Anomaly/Attack",
    "parameters": "Anomalous traffic patterns deviating from baseline (e.g., unusual byte counts or error rates).",
    "fix": "Investigate source IP, check firewall logs, isolate affected systems, and perform deep packet inspection."
}

# --- Sidebar Telemetry ---
st.sidebar.title("Live Telemetry")
st.sidebar.markdown("Server Core Node A-1")

cpu_placeholder = st.sidebar.empty()
mem_placeholder = st.sidebar.empty()
net_placeholder = st.sidebar.empty()

# Simulate live telemetry numbers (pseudo-randomized on run)
cpu_val = np.random.randint(40, 85)
mem_val = np.random.randint(50, 95)
net_val = np.random.uniform(1.2, 5.5)

cpu_placeholder.metric("CPU Load", f"{cpu_val}%")
st.sidebar.progress(cpu_val / 100)

mem_placeholder.metric("Memory Usage", f"{mem_val}%")
st.sidebar.progress(mem_val / 100)

net_placeholder.metric("Network Throughput", f"{net_val:.1f} Gbps")
st.sidebar.divider()
st.sidebar.info("System is actively monitoring incoming connections.")

# Load models and encoders
@st.cache_resource
def load_assets():
    rf_model = joblib.load("model.pkl")
    iso_model = joblib.load("iso_model.pkl")
    label_encoder = joblib.load("label_encoder.pkl")
    cat_encoders = joblib.load("cat_encoders.pkl")
    return rf_model, iso_model, label_encoder, cat_encoders

rf_model, iso_model, label_encoder, cat_encoders = load_assets()

# Header
st.title("Nexus: Threat Intelligence Platform")
st.markdown("Advanced Machine Learning intrusion detection using the **NSL-KDD dataset**.")
st.divider()

# File uploader
uploaded_file = st.file_uploader(
    "Upload Network Traffic CSV",
    type=["csv"]
)

if uploaded_file is not None:
    # Load uploaded CSV
    data = pd.read_csv(uploaded_file)
    
    st.subheader("Data Intake & Pre-processing")
    st.dataframe(data.head(10), use_container_width=True)

    # Encode categorical columns
    for col, encoder in cat_encoders.items():
        if col in data.columns:
            data[col] = encoder.transform(data[col])

    # Keep a clean feature copy for model predictions
    features = data.copy()

    # ---- Isolation Forest (Anomaly Detection) ----
    anomaly_preds = iso_model.predict(features)
    data["Anomaly Detection"] = ["Anomaly" if x == -1 else "Normal" for x in anomaly_preds]

    # ---- Random Forest (Attack Classification) ----
    rf_predictions = rf_model.predict(features)
    data["Prediction"] = label_encoder.inverse_transform(rf_predictions)

    # Threat scoring
    data["Threat Score"] = data["Prediction"].apply(lambda x: 0 if x == "normal" else 90)

    st.divider()

    # Metrics
    total_connections = len(data)
    detected_attacks = sum(data["Prediction"] != "normal")
    detected_anomalies = sum(data["Anomaly Detection"] == "Anomaly")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Connections Analyzed", total_connections)
    col2.metric("Verified Attacks", detected_attacks)
    col3.metric("Anomalies Detected", detected_anomalies)

    st.divider()

    # --- New Section: Detailed Attack Information ---
    if detected_attacks > 0:
        st.subheader("Threat Diagnostics")
        unique_attacks = data[data["Prediction"] != "normal"]["Prediction"].unique()
        
        for attack in unique_attacks:
            info = ATTACK_INFO.get(attack, DEFAULT_ATTACK)
            with st.expander(f"Threat Profile: {attack.upper()}", expanded=True):
                st.markdown(f"**Classification Type:** {info['type']}")
                st.markdown(f"**Key Parameters Suggesting Attack:** {info['parameters']}")
                st.markdown(f"**Recommended Fix/Mitigation:** {info['fix']}")
                
                # Show sample of rows that triggered this attack
                st.write("Intercepted Traffic Signature (Sample):")
                st.dataframe(data[data["Prediction"] == attack].head(3), use_container_width=True)
                
        st.divider()

        # --- New Section: Global Threat Map ---
        st.subheader("Global Threat Origin Map (Simulated)")
        st.markdown("Geographic projection of incoming malicious traffic vectors.")
        
        # Simulate lat/lon for the attacks (common hotspot regions)
        # Bounding box roughly corresponding to global internet hubs
        attack_data = data[data["Prediction"] != "normal"].copy()
        
        if len(attack_data) > 0:
            np.random.seed(42) # For consistent map plotting during demo
            
            # Generate random locations mostly centered around major continents
            lats = np.concatenate([
                np.random.normal(37.0, 5.0, int(len(attack_data)*0.4)),   # North America
                np.random.normal(50.0, 5.0, int(len(attack_data)*0.3)),   # Europe
                np.random.normal(30.0, 10.0, len(attack_data) - int(len(attack_data)*0.4) - int(len(attack_data)*0.3)) # Asia
            ])
            lons = np.concatenate([
                np.random.normal(-95.0, 15.0, int(len(attack_data)*0.4)), # North America
                np.random.normal(10.0, 10.0, int(len(attack_data)*0.3)),  # Europe
                np.random.normal(100.0, 15.0, len(attack_data) - int(len(attack_data)*0.4) - int(len(attack_data)*0.3)) # Asia
            ])
            
            attack_data['lat'] = lats[:len(attack_data)]
            attack_data['lon'] = lons[:len(attack_data)]
            
            st.map(attack_data, color="#ff4b4b", size=2000)

    st.divider()

    # --- Improved Graphs ---
    st.subheader("Traffic & Threat Distribution")
    
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        data['Traffic Status'] = data['Prediction'].apply(lambda x: 'Normal' if x == 'normal' else 'Attack')
        pie_data = data['Traffic Status'].value_counts().reset_index()
        pie_data.columns = ['Status', 'Count']
        
        fig_pie = px.pie(
            pie_data, 
            names='Status', 
            values='Count',
            title='Overall Traffic Status',
            hole=0.4,
            color='Status',
            color_discrete_map={'Normal': '#10b981', 'Attack': '#ef4444'}
        )
        fig_pie.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#e2e8f0'))
        st.plotly_chart(fig_pie, use_container_width=True)

    with chart_col2:
        attack_data_only = data[data['Prediction'] != 'normal']
        if not attack_data_only.empty:
            bar_data = attack_data_only['Prediction'].value_counts().reset_index()
            bar_data.columns = ['Attack Type', 'Count']
            
            fig_bar = px.bar(
                bar_data, 
                x='Attack Type', 
                y='Count',
                title='Frequency of Specific Threats',
                color='Attack Type',
                color_discrete_sequence=px.colors.qualitative.Bold
            )
            fig_bar.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#e2e8f0'))
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No threats detected to display specific distribution.")

    st.divider()
    
    # --- Export Report Button ---
    st.subheader("Export Intelligence Report")
    st.markdown("Download the complete analysis dataset with threat scores and predictions.")
    
    csv_data = data.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="Download CSV Report",
        data=csv_data,
        file_name="nexus_threat_report.csv",
        mime="text/csv",
        type="primary"
    )

else:
    # Landing page state
    st.info("Awaiting telemetry... Please upload a network traffic CSV file to initialize analysis.")
    st.markdown('''
        ### Core Capabilities:
        - Real-time zero-day classification using Random Forest
        - Deep Anomaly detection via Isolation Forest
        - Advanced diagnostics for identified threat vectors
        - Interactive global threat mapping
    ''')
