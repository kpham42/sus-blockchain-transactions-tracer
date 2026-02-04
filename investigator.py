import requests
import pandas as pd
import datetime
import matplotlib.pyplot as plt
import time
import os
from dotenv import load_dotenv

# --- CONFIGURATION ---

load_dotenv()

API_KEY = os.getenv("API_KEY")

if not API_KEY:
    print(" ERROR: Could not find 'ETHERSCAN_API_KEY' in your .env file.")
    print("   Make sure you created the .env file in the same folder as this script.")
    exit()

BASE_URL = "https://api.etherscan.io/v2/api" 

# Chain ID (1 = Ethereum Mainnet)
CHAIN_ID = "1"

# Known "Bad Actors" List
RISKY_ADDRESSES = {
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash Router",
    "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": "Tornado Cash (0.1 ETH)",
    "0x7f367cc41522ce07553e823bf3be79a889debe1b": "Exploiter (Generic)",
    "0x4b3406a41399c7fd2ba65cbc93697ad9e7ea61e5": "Fake Phishing Site",
    "0x098B716B8Aaf21512996dC57EB0615e2383E2f96": "Ronin Bridge Exploiter"
}

def get_transactions(address):
    """
    Fetches transaction history using the NEW V2 API.
    """
    time.sleep(0.2) 
    params = {
        "chainid": CHAIN_ID,      
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": 0,
        "endblock": 99999999,
        "sort": "desc",
        "apikey": API_KEY
    }
    
    try:
        response = requests.get(BASE_URL, params=params)
        data = response.json()
        
        # Check for API errors
        if data["message"] != "OK":
            # If "No transactions found", return empty list silently
            if "No transactions found" in data["message"]:
                return []
            # For other errors (like Invalid Key), print the error
            print(f"\n API ERROR: {data['message']}")
            print(f"   Details: {data.get('result', 'Unknown error')}\n")
            return []
            
        return data["result"][:50]
        
    except Exception as e:
        print(f"Connection error: {e}")
        return []

def analyze_risk(transactions, current_address, depth=0):
    """Same logic as before, just passed cleaner data."""
    alerts = []
    suspicious_destinations = []
    
    print(f"   [Depth {depth}] Scanning {len(transactions)} txs...")
    
    for tx in transactions:
        eth_value = float(tx["value"]) / 10**18
        tx_date = datetime.datetime.fromtimestamp(int(tx["timeStamp"]))
        
        # CHECK 1: Direct Exposure
        if tx["to"] in RISKY_ADDRESSES:
            alerts.append({
                "Date": tx_date,
                "Risk Type": "Direct Interaction",
                "Entity": RISKY_ADDRESSES[tx["to"]],
                "Amount": eth_value,
                "Hop": depth
            })

        # CHECK 2: Follow the Money (Outgoing > 2 ETH)
        if depth == 0 and tx["from"] == current_address and eth_value > 2:
            if tx["to"] not in RISKY_ADDRESSES:
                suspicious_destinations.append(tx["to"])
                alerts.append({
                    "Date": tx_date,
                    "Risk Type": "Potential Layering (Outgoing)",
                    "Entity": f"Suspect Wallet -> {tx['to'][:8]}...",
                    "Amount": eth_value,
                    "Hop": depth
                })

    return alerts, list(set(suspicious_destinations))

def trace_money_trail(target_address):
    print(f"\n PHASE 1: Analyzing Target {target_address}...")
    target_txs = get_transactions(target_address)
    
    primary_alerts, potential_mules = analyze_risk(target_txs, target_address, depth=0)
    all_alerts = primary_alerts
    
    # PHASE 2: Check the 'Mules'
    if potential_mules:
        print(f"\n PHASE 2: Following the money ({len(potential_mules)} destinations)...")
        for mule_address in potential_mules:
            mule_txs = get_transactions(mule_address)
            mule_alerts, _ = analyze_risk(mule_txs, mule_address, depth=1)
            
            if mule_alerts:
                print(f" HIDDEN RISK FOUND in {mule_address}")
                for alert in mule_alerts:
                    alert["Risk Type"] = "Indirect Connection (Layering)"
                    alert["Entity"] = f"{alert['Entity']} (via {mule_address[:8]})"
                    all_alerts.append(alert)
    return all_alerts

def visualize_investigation(alerts):
    if not alerts: return
    df = pd.DataFrame(alerts)
    plt.figure(figsize=(10, 6))
    
    colors = {
        'Direct Interaction': '#ff0000', 
        'Indirect Connection (Layering)': '#ff9900',
        'Potential Layering (Outgoing)': '#0000ff'
    }
    
    for r_type in df['Risk Type'].unique():
        subset = df[df['Risk Type'] == r_type]
        c = colors.get(r_type, 'gray')
        plt.scatter(subset['Date'], subset['Amount'], label=r_type, color=c, s=100, edgecolors='k', alpha=0.7)

    plt.title("Money Trail & Risk Timeline")
    plt.xlabel("Date")
    plt.ylabel("ETH Amount")
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.gcf().autofmt_xdate()
    plt.show()

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    print("--- BLOCKCHAIN FORENSICS TOOL V2.0 (Etherscan V2 Updated) ---")
    user_input = input("Enter Target Address: ").strip().lower()
    
    if user_input.startswith("0x") and len(user_input) == 42:
        report = trace_money_trail(user_input)
        if report:
            print("\n" + "="*50)
            print(f" FINAL REPORT")
            print("="*50)
            for alert in report:
                print(f"• {alert['Risk Type']} | {alert['Amount']} ETH | {alert['Entity']}")
            visualize_investigation(report)
        else:
            print(" No suspicious trails found.")
