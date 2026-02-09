import requests
import pandas as pd
import datetime
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
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
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash (1 ETH)",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash (10 ETH)",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash (100 ETH)",
    "0x7f367cc41522ce07553e823bf3be79a889debe1b": "Exploiter (Generic)",
    "0x4b3406a41399c7fd2ba65cbc93697ad9e7ea61e5": "Fake Phishing Site",
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96": "Ronin Bridge Exploiter",
    "0x8589427373d6d84e98730d7795d8f6f8731fda16": "Ronin Bridge Exploiter 2",
    "0xba214c1c1928a32bffe790263e38b4af9bfcd659": "OFAC Sanctioned Entity",
    "0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a": "OFAC Sanctioned Entity 2",
    "0x7db418b5d567a4e0e8c59ad71be1fce48f3e6107": "OFAC Sanctioned Entity 3",
}

def get_transactions(address):
    """Fetches transaction history using the Etherscan V2 API."""
    time.sleep(0.25)
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

        if data["message"] != "OK":
            if "No transactions found" in data["message"]:
                return []
            print(f"\n API ERROR: {data['message']}")
            print(f"   Details: {data.get('result', 'Unknown error')}\n")
            return []

        return data["result"][:50]

    except Exception as e:
        print(f"Connection error: {e}")
        return []


def analyze_risk(transactions, current_address, depth=0):
    """Analyze transactions for risk indicators at a given hop depth."""
    alerts = []
    suspicious_destinations = []

    print(f"   [Depth {depth}] Scanning {len(transactions)} txs...")

    for tx in transactions:
        eth_value = float(tx["value"]) / 10**18
        tx_date = datetime.datetime.fromtimestamp(int(tx["timeStamp"]))

        # CHECK 1: Direct Exposure to known bad actors
        if tx["to"] in RISKY_ADDRESSES:
            alerts.append({
                "Date": tx_date,
                "Risk Type": "Direct Interaction",
                "Entity": RISKY_ADDRESSES[tx["to"]],
                "Amount": eth_value,
                "Hop": depth
            })

        if tx["from"] in RISKY_ADDRESSES:
            alerts.append({
                "Date": tx_date,
                "Risk Type": "Direct Interaction",
                "Entity": f"Inflow from {RISKY_ADDRESSES[tx['from']]}",
                "Amount": eth_value,
                "Hop": depth
            })

        # CHECK 2: Follow the Money (Outgoing > 2 ETH to unknown wallets)
        if depth == 0 and tx["from"].lower() == current_address.lower() and eth_value > 2:
            if tx["to"] not in RISKY_ADDRESSES:
                suspicious_destinations.append(tx["to"])
                alerts.append({
                    "Date": tx_date,
                    "Risk Type": "Potential Layering (Outgoing)",
                    "Entity": f"Suspect Wallet -> {tx['to'][:10]}...",
                    "Amount": eth_value,
                    "Hop": depth
                })

    return alerts, list(set(suspicious_destinations))


def trace_money_trail(target_address):
    """Two-phase investigation: scan target, then follow suspicious outflows."""
    print(f"\n PHASE 1: Analyzing Target {target_address}...")
    target_txs = get_transactions(target_address)

    primary_alerts, potential_mules = analyze_risk(target_txs, target_address, depth=0)
    all_alerts = primary_alerts

    # PHASE 2: Check the downstream wallets
    if potential_mules:
        print(f"\n PHASE 2: Following the money ({len(potential_mules)} destinations)...")
        for mule_address in potential_mules[:10]:  # cap at 10 to avoid rate limits
            mule_txs = get_transactions(mule_address)
            mule_alerts, _ = analyze_risk(mule_txs, mule_address, depth=1)

            if mule_alerts:
                print(f"   HIDDEN RISK FOUND in {mule_address}")
                for alert in mule_alerts:
                    alert["Risk Type"] = "Indirect Connection (Layering)"
                    alert["Entity"] = f"{alert['Entity']} (via {mule_address[:10]})"
                    all_alerts.append(alert)

    return all_alerts


def compute_risk_score(df):
    """Compute a 0-100 risk score from alert data."""
    direct = len(df[df['Risk Type'] == 'Direct Interaction'])
    indirect = len(df[df['Risk Type'] == 'Indirect Connection (Layering)'])
    layering = len(df[df['Risk Type'] == 'Potential Layering (Outgoing)'])
    total_eth = df['Amount'].sum()

    score = min(100, (direct * 25) + (indirect * 15) + (layering * 5) + int(total_eth * 0.5))
    return score


def visualize_investigation(alerts):
    """
    Generate a multi-panel investigation report.
    Uses constrained_layout for automatic spacing — no more overlap.
    """
    if not alerts:
        print("No alerts to visualize.")
        return

    df = pd.DataFrame(alerts)

    colors = {
        'Direct Interaction': '#e74c3c',
        'Indirect Connection (Layering)': '#f39c12',
        'Potential Layering (Outgoing)': '#3498db'
    }

    # ---------------------------------------------------------------
    # KEY FIX: constrained_layout=True handles ALL spacing automatically.
    # Each row gets 5 inches of height so nothing is cramped.
    # ---------------------------------------------------------------
    fig, axes = plt.subplots(
        nrows=3, ncols=2,
        figsize=(16, 18),
        constrained_layout=True,
        gridspec_kw={'height_ratios': [1.2, 1, 0.6]}
    )

    # ── Panel 1: Risk Event Timeline (top row, full width) ──
    ax_timeline = fig.add_subplot(3, 1, 1)
    axes[0, 0].set_visible(False)
    axes[0, 1].set_visible(False)

    for r_type in df['Risk Type'].unique():
        subset = df[df['Risk Type'] == r_type]
        ax_timeline.scatter(
            subset['Date'], subset['Amount'],
            label=r_type, color=colors.get(r_type, 'gray'),
            s=140, edgecolors='black', alpha=0.75, linewidth=1.2, zorder=3
        )

    # Annotate top 3 highest-value events
    top3 = df.nlargest(3, 'Amount')
    for _, row in top3.iterrows():
        ax_timeline.annotate(
            f"{row['Amount']:.2f} ETH\n{row['Entity'][:25]}",
            xy=(row['Date'], row['Amount']),
            xytext=(15, 15), textcoords='offset points',
            fontsize=8, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.4', fc='#ffffcc', ec='gray', alpha=0.9),
            arrowprops=dict(arrowstyle='->', color='gray', lw=1.2)
        )

    ax_timeline.set_title('Risk Event Timeline', fontsize=14, fontweight='bold', pad=12)
    ax_timeline.set_ylabel('ETH Amount', fontsize=11)
    ax_timeline.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    ax_timeline.tick_params(axis='x', rotation=30)
    ax_timeline.legend(fontsize=9, loc='upper left', framealpha=0.9)
    ax_timeline.grid(True, linestyle='--', alpha=0.3)

    # ── Panel 2: Risk Type Distribution (middle-left) ──
    ax_bar = axes[1, 0]
    risk_counts = df['Risk Type'].value_counts()
    bar_colors = [colors.get(rt, 'gray') for rt in risk_counts.index]
    bars = ax_bar.barh(risk_counts.index, risk_counts.values, color=bar_colors, edgecolor='black', linewidth=0.8)

    for bar, val in zip(bars, risk_counts.values):
        ax_bar.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                    str(val), va='center', fontweight='bold', fontsize=11)

    ax_bar.set_title('Alert Counts by Risk Type', fontsize=13, fontweight='bold', pad=10)
    ax_bar.set_xlabel('Count')
    ax_bar.invert_yaxis()

    # ── Panel 3: ETH Volume by Entity (middle-right) ──
    ax_entity = axes[1, 1]
    entity_vol = df.groupby('Entity')['Amount'].sum().sort_values(ascending=True).tail(8)
    entity_colors = ['#e74c3c' if any(k in ent for k in ['Tornado', 'Exploit', 'OFAC', 'Phish']) else '#3498db'
                     for ent in entity_vol.index]
    short_labels = [e[:30] + '...' if len(e) > 30 else e for e in entity_vol.index]
    ax_entity.barh(short_labels, entity_vol.values, color=entity_colors, edgecolor='black', linewidth=0.8)

    for i, val in enumerate(entity_vol.values):
        ax_entity.text(val + 0.1, i, f"{val:.2f}", va='center', fontsize=9, fontweight='bold')

    ax_entity.set_title('ETH Volume by Entity (Top 8)', fontsize=13, fontweight='bold', pad=10)
    ax_entity.set_xlabel('ETH')

    # ── Panel 4: Summary Stats (bottom-left) ──
    ax_summary = axes[2, 0]
    ax_summary.axis('off')

    direct_n = len(df[df['Risk Type'] == 'Direct Interaction'])
    indirect_n = len(df[df['Risk Type'] == 'Indirect Connection (Layering)'])
    total_eth = df['Amount'].sum()
    risk_score = compute_risk_score(df)

    summary_lines = [
        f"Total Alerts:            {len(df)}",
        f"Direct Interactions:     {direct_n}",
        f"Indirect Connections:    {indirect_n}",
        f"Total ETH Flagged:       {total_eth:.4f}",
        f"Unique Entities:         {df['Entity'].nunique()}",
    ]
    summary_text = "\n".join(summary_lines)
    ax_summary.text(
        0.05, 0.5, summary_text,
        transform=ax_summary.transAxes,
        fontfamily='monospace', fontsize=11, va='center',
        bbox=dict(boxstyle='round,pad=0.8', fc='#f0f0f0', ec='black', lw=1.5)
    )
    ax_summary.set_title('Investigation Summary', fontsize=13, fontweight='bold', pad=10)

    # ── Panel 5: Risk Score Gauge (bottom-right) ──
    ax_gauge = axes[2, 1]
    ax_gauge.axis('off')

    if risk_score < 30:
        level, color = "LOW RISK", "#27ae60"
    elif risk_score < 60:
        level, color = "MODERATE RISK", "#f39c12"
    else:
        level, color = "HIGH RISK", "#e74c3c"

    ax_gauge.text(
        0.5, 0.5,
        f"RISK SCORE: {risk_score}/100\n{level}",
        transform=ax_gauge.transAxes,
        ha='center', va='center',
        fontsize=18, fontweight='bold', color='white',
        bbox=dict(boxstyle='round,pad=1.0', fc=color, ec='black', lw=2.5)
    )

    # ── Save ──
    fig.suptitle('Blockchain Forensics Investigation Report',
                 fontsize=18, fontweight='bold')

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"investigation_report_{timestamp}.png"
    fig.savefig(filename, dpi=200, facecolor='white')
    print(f"\n Report saved as: {filename}")
    plt.show()


# --- MAIN EXECUTION ---
if __name__ == "__main__":
    print("--- BLOCKCHAIN FORENSICS TOOL V2.0 (Etherscan V2 Updated) ---")
    user_input = input("Enter Target Address: ").strip().lower()

    if user_input.startswith("0x") and len(user_input) == 42:
        report = trace_money_trail(user_input)
        if report:
            print("\n" + "=" * 50)
            print(" FINAL REPORT")
            print("=" * 50)
            for alert in report:
                print(f"  {alert['Risk Type']} | {alert['Amount']:.4f} ETH | {alert['Entity']}")
            visualize_investigation(report)
        else:
            print(" No suspicious trails found.")
    else:
        print(" Invalid address. Must start with 0x and be 42 characters.")