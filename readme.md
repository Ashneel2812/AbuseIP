# AbuseIP

A Python tool to fetch, analyze, and report on abusive IP addresses using AbuseIPDB and VirusTotal, with MongoDB storage and email reporting.

## Features

- Fetches blacklist from AbuseIPDB
- Samples IPs and fetches VirusTotal reports
- Stores results in MongoDB
- Sends summary email with Excel and HTML table

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/Ashneel2812/AbuseIP.git
   cd AbuseIP
   ```
2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
3. **Set up environment variables:**
   Create a `.env` file in the project root with the following variables:
   ```env
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   VT_API_KEY=your_virustotal_api_key
   MONGO_URI=your_mongodb_uri
   EMAIL_SENDER=your_email_address
   EMAIL_PASSWORD=your_email_password
   EMAIL_RECEIVER=receiver_email_address
   SMTP_SERVER=smtp.yourprovider.com
   SMTP_PORT=587
   ```

## Usage

Run the main script:
```sh
python main.py
```

## How it Works

1. Downloads blacklist from AbuseIPDB and saves it as `abuse_list.xlsx`.
2. Samples 5 random IPs and adds 1 known malicious IP for demonstration.
3. Fetches VirusTotal data for each IP (rate-limited to 4/min).
4. Stores results in MongoDB (`AbuseIP.AbuseVT` collection).
5. Sends an email with the Excel attachment and an HTML summary table.

## Configuration

- **abuse_list.xlsx**: Output Excel file containing the AbuseIPDB blacklist.
- **mongo-setup.png**: MongoDB connection diagram (included in the email).
- **Environment Variables**: All sensitive keys and configuration are managed via `.env`.

## Dependencies

- requests
- pandas
- pycountry
- python-dotenv
- pymongo
- tabulate
- smtplib
- email

Install all dependencies with:
```sh
pip install -r requirements.txt
```

## License

MIT

## Contact

Ashneel  
[GitHub Repository](https://github.com/Ashneel2812/AbuseIP)
