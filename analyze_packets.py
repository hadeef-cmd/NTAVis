import pandas as pd
import matplotlib.pyplot as plt

# Load the CSV file
df = pd.read_csv("packets.csv")

print("First 5 rows of data:")
print(df.head())

# Count packets per Source IP
src_counts = df["Source IP"].value_counts()

# Plot top 5 Source IPs
src_counts.head(5).plot(kind="bar", title="Top 5 Source IPs")
plt.xlabel("Source IP")
plt.ylabel("Packet Count")
plt.tight_layout()
plt.savefig("top_source_ips.png") # save instead of show
plt.close()

# Count packets by protocol
proto_counts = df["Protocol"].value_counts()
proto_counts.plot(kind="bar", title="Protocol Distribution")
plt.xlabel("Protocol Number")
plt.ylabel("Packet Count")
plt.tight_layout()
plt.savefig("protocol_distribution.png")
plt.close()

print("✅ Charts saved as top_source_ips.png and protocol_distribution.png")
