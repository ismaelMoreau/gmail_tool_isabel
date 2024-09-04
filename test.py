import os
import base64
import datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import PyPDF2
import logging

# Set up logging
logging.basicConfig(filename="attachment_errors.log", level=print, format="%(asctime)s - %(levelname)s - %(message)s")

# If modifying these SCOPES, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

# Directory to save attachments
attachment_dir = "attachments\\"

# Whitelist text file (domains only)
whitelist_file = "whitelist.txt"

# Words to search for in the PDFs
search_words = ["facture", "invoice"]

def load_whitelist():
    if os.path.exists(whitelist_file):
        with open(whitelist_file, 'r') as file:
            return [line.strip() for line in file.readlines()]
    return []

def authenticate_gmail():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

def fetch_emails(service, whitelist):
    results = service.users().messages().list(userId='me').execute()
    messages = results.get('messages', [])
    
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        headers = msg.get('payload', {}).get('headers', [])
        from_email = None
        for header in headers:
            if header['name'] == 'From':
                from_email = header['value']
                break
        domain = from_email.split('@')[-1][:-1]
        if from_email and any(whitelisted_domain in domain for whitelisted_domain in whitelist):
            print(f"Email from {from_email}:")
            print("Subject:", get_header(headers, 'Subject'))
            #print("Body:", get_body(msg))
            download_attachments(service, msg, domain)
            archive_email(service, message['id'],domain)

def get_header(headers, name):
    for header in headers:
        if header['name'] == name:
            return header['value']
    return None

def get_body(msg):
    parts = msg.get('payload', {}).get('parts', [])
    for part in parts:
        if part.get('mimeType') == 'text/plain':
            body = part['body'].get('data')
            if body:
                return base64.urlsafe_b64decode(body).decode('utf-8')
    return None

def download_attachments(service, msg, domain):
    parts = msg.get('payload', {}).get('parts', [])
    for part in parts:
        if 'filename' in part and part['filename'].endswith('.pdf'):
            att_id = part['body'].get('attachmentId')
            attachment = service.users().messages().attachments().get(
                userId='me', messageId=msg['id'], id=att_id).execute()
            data = base64.urlsafe_b64decode(attachment['data'])
            save_attachment(part['filename'], data, domain)

def save_attachment(filename, data, domain):
    try:
        # Create the domain directory with matching and non_matching subdirectories
        domain_dir = os.path.join(attachment_dir, domain)
        matching_dir = os.path.join(domain_dir, "factures")
        non_matching_dir = os.path.join(domain_dir, "autres")

        for dir_path in [matching_dir, non_matching_dir]:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)

        # Add domain and date to the filename
        date_str = datetime.datetime.now().strftime("%Y%m%d")
        new_filename = f"{domain}{date_str}_{os.path.splitext(filename)[0]}_.pdf"

        # Temporarily save the file to the domain directory for word check
        temp_filepath = os.path.join(domain_dir, new_filename)
        with open(temp_filepath, 'wb') as f:
            f.write(data)

        # Check if any of the words are in the PDF
        if is_word_in_pdf(temp_filepath, search_words):
            final_filepath = os.path.join(matching_dir, new_filename)
        else:
            final_filepath = os.path.join(non_matching_dir, new_filename)

        # Move the file to the appropriate folder
        os.rename(temp_filepath, final_filepath)
        print(f"Saved attachment to {final_filepath}")

    except FileExistsError as e:
        print(f"FileExistsError: {e} - {new_filename}")
    except Exception as e:
        print(f"Error: {e} - {new_filename}")


def is_word_in_pdf(pdf_path, words):
    with open(pdf_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        for page_num in range(len(reader.pages)):
            page = reader.pages[page_num]
            text = page.extract_text()
            for word in words:
                if word.lower() in text.lower():
                    return True
    return False

def archive_email(service, message_id, domain):
    try:
        # Create the label name based on the email domain
        label_name = f"Archived/{domain}"
        
        # Check if the label exists; if not, create it
        labels = service.users().labels().list(userId='me').execute().get('labels', [])
        label_id = None
        for label in labels:
            if label['name'] == label_name:
                label_id = label['id']
                break
        
        if not label_id:
            label = service.users().labels().create(
                userId='me',
                body={'name': label_name, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'}
            ).execute()
            label_id = label['id']
        
        # Move the email to the domain-specific subfolder by applying the label and removing 'INBOX'
        service.users().messages().modify(
            userId='me', id=message_id, body={
                'addLabelIds': [label_id],
                'removeLabelIds': ['INBOX']
            }
        ).execute()
        print(f"Email {message_id} archived under {label_name}.")
    except Exception as e:
        print(f"Error archiving email {message_id} under {label_name}: {e}")


def main():
    whitelist = load_whitelist()
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)
    fetch_emails(service, whitelist)


if __name__ == '__main__':
    main()
