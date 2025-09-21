import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st

# Protocol mapping (numbers → names)
proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Load the CSV
df = pd.read_csv("packets.csv")

st.title("📊 Network Traffic Dashboard")
st.write("Final Year Project – Real-time Threat Detection (Demo)")

st.subheader("First 10 Packets")
st.dataframe(df.head(10))

# --- Top 5 Source IPs ---
st.subheader("Top 5 Source IPs")
src_counts = df["Source IP"].value_counts().head(5)
st.bar_chart(src_counts)

# --- Protocol Distribution ---
st.subheader("Protocol Distribution")
df["Protocol Name"] = df["Protocol"].map(proto_map).fillna(df["Protocol"])
proto_counts = df["Protocol Name"].value_counts()
st.bar_chart(proto_counts)
