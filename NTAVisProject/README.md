# NTAVis: Network Traffic Analysis & Visualization

NTAVis is a real-time network monitoring tool built with Python and Streamlit. It captures and analyzes network traffic to detect threats, provides an interactive dashboard for visualization, and includes features for threat management.

## Features

- **Real-time Packet Analysis**: Captures and inspects live network traffic.
- **Threat Detection**: Identifies Malformed packets, Suspicious activity, SYN Floods, and UDP Floods.
- **Secure OTP Login**: Two-factor authentication using One-Time Passwords sent via email.
- **Interactive Dashboard**:
    - **Overview**: High-level metrics and raw packet data.
    - **Geo Map**: Visualizes the geographic source of threats.
    - **Analytics**: Charts for threat types, protocols, and activity over time.
- **IP Address Filtering**: Search for specific source IPs within the raw data.
- **Downloadable Reports**: Export filtered data to a CSV file.
- **Simulated Defense**: A "Block IP" feature to simulate adding malicious IPs to a blocklist.
- **Secrets Management**: Securely manages credentials using Streamlit's secrets manager.

## Setup & Installation

### 1. Prerequisites
- Python 3.8+
- Pip

### 2. Clone the Repository
(Or just use your local project folder)

### 3. Install Dependencies
Install all required Python packages.
```bash
pip install -r requirements.txt
```

### 4. Configure Secrets
Create a file at `.streamlit/secrets.toml` and add your credentials. This keeps them secure and out of the main code.

```toml
# .streamlit/secrets.toml

[gmail]
email = "your_email@gmail.com"
app_password = "your_gmail_app_password"

[login]
username = "your_dashboard_username"
password = "your_dashboard_password"
```

##  How to Run

1.  **Start the Packet Capture** (in a separate terminal, if needed):
    ```bash
    sudo python3 capture.py
    ```

2.  **Run the Streamlit Dashboard:**
    ```bash
    streamlit run app.py
    ```

3.  Open your browser to the local URL provided by Streamlit, and log in using your credentials and the OTP sent to your email.

## 📝 License

This project is for academic and demonstration purposes only. See the `LICENSE` file for more details.

## 👨 Author

- Muhammad Hadif Shah Bin Mohd Hadli Shah
