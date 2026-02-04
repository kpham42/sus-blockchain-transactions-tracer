# sus-blockchain-transactions-tracer

I designed this tracer to automate the manual grunt work of investigating Ethereum wallets. Manually clicking through Etherscan tabs to trace funds is inefficient, so basically this tool handles the pattern recognition for me.

It specifically looks for "layering", which is the process where bad actors move funds through a series of clean wallets to hide the origin. If the script detects a transfer to a fresh address, it automatically follows the transaction to see if that second wallet interacts with any known illicit entities.

## What it actually does

**Whale Monitoring**: I set a default threshold of 2 ETH. The script flags any transaction above this amount, as large movements are often the starting point of an investigation.

**Bad Actor Detection**: It cross-references transactions against a list of known high-risk addresses (Tornado Cash, specific exploiters, phishing contracts).

**Multi-Hop Analysis**: This is the core logic. If the target sends funds to an unknown address, the script triggers a recursive scan on that destination. It’s useful for catching "mules" that look clean on the surface but are just pass-throughs for mixers.

**Visualization**: It uses matplotlib to plot a timeline of the risk events. Reading CSVs is fine, but seeing the timing of a large transfer followed immediately by a mixer deposit makes the intent much clearer.

## Setup

### 1. Dependencies

You'll need Python 3. Install the libraries I used:

pip install -r requirements.txt


### 2. Etherscan API Key

The script relies on Etherscan's V2 API. You will need your own key to avoid rate limits.

Get a free key at Etherscan.io.

Make sure to not share it. I placed mines in an enviromental variable (as anyone should). If you are using it for personal use, feel free to do whatever you need.

### 3. Configuration

I configured the script to look for environment variables rather than hardcoding credentials.

Create a file named .env in the root folder.

Add your key there:

`ETHERSCAN_API_KEY=Your_Copied_Key_Here`

## Usage

Run the script directly:

`python investigator.py`

It will ask for a target address.

## Validation

If you want to see how it handles a real positive hit, test it against the Ronin Bridge Exploiter address. It has enough history to trigger both the direct interaction flags and the volume alerts:

`0x098B716B8Aaf21512996dC57EB0615e2383E2f96`
