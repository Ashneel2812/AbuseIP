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
from email.utils import make_msgid
from email.mime.image import MIMEImage

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


def fetch_abuseipdb_blacklist_to_excel(output_filename='abuse_list.xlsx'):
    url = 'https://api.abuseipdb.com/api/v2/blacklist?ipVersion=4'
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Failed to fetch data from AbuseIPDB. Status code: {response.status_code}")
            return

        data = response.json()
        ip_data = data.get('data', [])

        if not ip_data:
            print("No data received from AbuseIPDB.")
            return

        formatted_data = []
        for entry in ip_data:
            ip = entry.get('ipAddress')
            score = entry.get('abuseConfidenceScore')
            country_code = entry.get('countryCode')
            country_name = get_country_name(country_code)

            formatted_data.append({
                'ipAddress': ip,
                'abuseConfidenceScore': score,
                'countryCode': country_code,
                'countryName': country_name
            })

        df = pd.DataFrame(formatted_data)
        df.to_excel(output_filename, index=False)
        print(f"Saved AbuseIPDB blacklist to {output_filename}")

    except Exception as e:
        print(f"Error fetching data from AbuseIPDB: {e}")


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

    image_cid = make_msgid(domain='inline.image')[1:-1]  # Strip < >

    image_path = "mongo-setup.png"
    if os.path.exists(image_path):
        with open(image_path, 'rb') as img_file:
            img_data = img_file.read()
            msg.get_payload()
            msg.add_related(img_data, maintype='image', subtype='png', cid=f"<{image_cid}>")

    msg.add_alternative(f"""
    <html>
        <body>
            <p>Hello,</p>
            <p>Please find attached the abuse IP report in Excel format, and below is the summary table generated using VirusTotal data.</p>

            <p><b>GitHub Repository:</b> 
                <a href="https://github.com/Ashneel2812/AbuseIP">https://github.com/Ashneel2812/AbuseIP</a>
            </p>

            <p><b>VirusTotal API Version:</b><br>
            I used the <code>v2</code> endpoint of VirusTotal instead of <code>v3</code> because v3 does not return fields like:
            <ul>
                <li>detected_urls</li>
                <li>detected_downloaded_samples</li>
                <li>undetected_downloaded_samples</li>
                <li>undetected_urls</li>
            </ul>
            These fields were essential to building the IP abuse summary.
            </p>

            <p><b>Planned Workflow:</b><br>
            The AbuseIPDB API returns 10,000 IPs in random order, so detecting new entries is resource-heavy. VirusTotal has a strict rate limit (4/min), which makes checking all IPs impractical. Hence, 5 random IPs were sampled and a known malicious IP was manually added for demo.
            </p>

            <p><b>VirusTotal Summary Table:</b></p>
            {body_html}

            <p><b>MongoDB Connection Diagram:</b><br>
            <img src="cid:{image_cid}" alt="MongoDB Diagram" style="width:600px;"><br><br></p>

            <p><b>Libraries Used:</b><br>
            <code>requests</code>, <code>pymongo</code>, <code>dotenv</code>, <code>smtplib</code>, <code>email</code>, <code>pycountry</code>, <code>pandas</code>
            </p>

            <p>Best regards,<br>I Ashneel</p>
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

    fetch_abuseipdb_blacklist_to_excel('abuse_list.xlsx')
    df = pd.read_excel(ABUSE_EXCEL)
    random_6 = df.sample(n=5).to_dict(orient='records')
    random_6.append({
        'ipAddress': '188.225.21.131',
        'abuseConfidenceScore': 100,
        'countryCode': 'RU',
        'countryName': 'Russian Federation'
    })

    vt_results = []

    for entry in random_6:
        ip = entry['ipAddress']
        vt_data = fetch_virustotal(ip)
        if vt_data:
            vt_results.append(vt_data)
            vt_collection.insert_one(vt_data)
            print(f"Inserted VT data for IP: {ip}")
        time.sleep(16)

    # Create table
    table_text = format_vt_data_for_email_table(vt_results)

    # Send email
    send_email_with_attachment(
    subject="AbuseIP Report - I Ashneel",
    body_html=format_vt_data_for_email_table(vt_results),
    filename=ABUSE_EXCEL
    )

    print("Process complete.")

if __name__ == '__main__':
    main()
