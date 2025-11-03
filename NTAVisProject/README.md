# NTAVis - Network Traffic Analysis & Visualization System

NTAVis is a Python-based tool for real-time network packet capture, threat analysis, and visualization. It uses Scapy for packet sniffing and Streamlit for an interactive web-based dashboard.

## Features

*   **Real-Time Packet Capture:** Captures network traffic on a specified interface.
*   **Threat Detection:** Identifies suspicious patterns like SYN/UDP floods and malformed packets.
*   **Geolocation:** Maps the geographical source of suspicious IP addresses.
*   **Interactive Dashboard:** A Streamlit application to view threat overviews, raw packet data, and analytics charts.
*   **Secure Login:** Features a two-factor authentication (OTP) system for the first login.

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/hadeef-cmd/NTAVis.git
    cd NTAVis
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv fyp_env
    source fyp_env/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Secrets:**
    Create a file at `.streamlit/secrets.toml` and add your credentials:
    ```toml
    # .streamlit/secrets.toml

    [gmail]
    email = "your-email@gmail.com"
    app_password = "your-16-digit-app-password"

    [login]
    username = "your_username"
    password = "your_password"
    ```

## How to Run

1.  **Start the Packet Capture (requires sudo):**
    Open a terminal and run:
    ```bash
    sudo python3 capture.py
    ```

2.  **Run the Streamlit Dashboard:**
    Open a second terminal and run:
    ```bash
    streamlit run app.py
    ```

3.  Open your web browser to the URL provided by Streamlit (usually `http://localhost:8501`).
