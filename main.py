import os
import time
import requests
import pandas as pd
import pycountry
from dotenv import load_dotenv
from pymongo import MongoClient
from tabulate import tabulate
import smtplib
from email.message import EmailMessage

# Load environment variables
load_dotenv()
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
VT_API_KEY = os.getenv('VT_API_KEY')
MONGO_URI = os.getenv('MONGO_URI')
EMAIL_SENDER = os.getenv('EMAIL_SENDER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
EMAIL_RECEIVER = os.getenv('EMAIL_RECEIVER')
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))

# MongoDB setup
mongo_client = MongoClient(MONGO_URI) if MONGO_URI else None
abuse_db = mongo_client['AbuseIP'] if mongo_client is not None else None
vt_collection = abuse_db['AbuseVT'] if abuse_db is not None else None

ABUSE_EXCEL = 'abuse_list.xlsx'

def get_country_name(code):
    try:
        return pycountry.countries.get(alpha_2=code).name
    except Exception:
        return ''

def fetch_virustotal(ip):
    url = f'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={VT_API_KEY}&ip={ip}'
    resp = requests.get(url)
    if resp.status_code != 200:
        print(f"Failed to fetch data for IP: {ip}")
        return None
    data = resp.json()

    detected_urls = [item['url'] for item in data.get('detected_urls', []) if isinstance(item, dict) and 'url' in item]
    undetected_urls = [item[0] for item in data.get('undetected_urls', []) if isinstance(item, list) and item]

    return {
        'ipAddress': ip,
        'country': data.get('country', ''),
        'detected_urls': detected_urls,
        'detected_downloaded_samples': data.get('detected_downloaded_samples', []),
        'undetected_downloaded_samples': data.get('undetected_downloaded_samples', []),
        'undetected_urls': undetected_urls
    }

def truncate_list(lst, max_items=5):
    return lst[:max_items] + ['...'] if len(lst) > max_items else lst

def format_vt_data_for_email_table(vt_data_list):
    html = "<table border='1' cellspacing='0' cellpadding='5' style='border-collapse: collapse;'>"
    html += "<tr><th>IP</th><th>Country</th><th>Detected URLs</th><th>Undetected URLs</th><th>Detected Samples</th><th>Undetected Samples</th></tr>"
    
    for data in vt_data_list:
        detected_urls = truncate_list(data.get('detected_urls', []))
        undetected_urls = truncate_list(data.get('undetected_urls', []))

        html += "<tr>"
        html += f"<td>{data['ipAddress']}</td>"
        html += f"<td>{data.get('country', '')}</td>"
        html += f"<td>{'<br>'.join(detected_urls)}</td>"
        html += f"<td>{'<br>'.join(undetected_urls)}</td>"
        html += f"<td>{len(data.get('detected_downloaded_samples', []))}</td>"
        html += f"<td>{len(data.get('undetected_downloaded_samples', []))}</td>"
        html += "</tr>"
    
    html += "</table>"
    return html


def send_email_with_attachment(subject, body_html, filename):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    msg.set_content("This email contains HTML content. Please view in an HTML-compatible email client.")
    msg.add_alternative(f"""
    <html>
        <body>
            <p>Attached is the abuse IP list.<br>Below is the VirusTotal summary:</p>
            {body_html}
        </body>
    </html>
    """, subtype='html')

    with open(filename, 'rb') as f:
        file_data = f.read()
        file_name = os.path.basename(filename)
        msg.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=file_name)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
            print(f"Email sent to {EMAIL_RECEIVER}")
    except Exception as e:
        print(f"Error sending email: {e}")


def main():
    df = pd.read_excel(ABUSE_EXCEL)
    top_5 = df.sample(n=5).to_dict(orient='records')
    top_5.append({
        'ipAddress': '188.225.21.131',
        'abuseConfidenceScore': 100,
        'countryCode': 'RU',
        'countryName': 'Russian Federation'
    })

    vt_results = []

    for entry in top_5:
        ip = entry['ipAddress']
        vt_data = fetch_virustotal(ip)
        if vt_data:
            vt_results.append(vt_data)
            vt_collection.insert_one(vt_data)
            print(f"Inserted VT data for IP: {ip}")
        time.sleep(16)

    # Prepare table
    table_text = format_vt_data_for_email_table(vt_results)

    # Send email with table and Excel attachment
    send_email_with_attachment(
    subject="AbuseIP Report - I Ashneel",
    body_html=format_vt_data_for_email_table(vt_results),
    filename=ABUSE_EXCEL
    )

    print("Process complete.")

if __name__ == '__main__':
    main()
