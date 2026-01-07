import os
import json
import base64
import re
import io
from datetime import datetime, timedelta
from flask import Flask, redirect, url_for, session, request, render_template, send_file, abort
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

app = Flask(__name__, template_folder='../templates')
app.secret_key = os.environ.get("SECRET_KEY", "your_secret_key")
app.config['JSON_AS_ASCII'] = False

# 권한 범위
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_google_config():
    """환경 변수에서 구글 설정 JSON을 읽어옵니다."""
    raw_config = os.environ.get("GOOGLE_CREDENTIALS")
    if not raw_config:
        return None
    return json.loads(raw_config)

def get_credentials():
    """세션에 저장된 토큰에서 Credentials 객체를 생성합니다."""
    token_info = session.get('token')
    if not token_info:
        return None
    return Credentials.from_authorized_user_info(token_info, SCOPES)

def get_message_content(payload):
    """메일 본문(HTML 우선, 없으면 Text) 추출 헬퍼 함수"""
    html = ""
    text = ""
    
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/html':
                data = part['body'].get('data')
                if data: html += base64.urlsafe_b64decode(data).decode('utf-8')
            elif part['mimeType'] == 'text/plain':
                data = part['body'].get('data')
                if data: text += base64.urlsafe_b64decode(data).decode('utf-8')
            elif 'parts' in part:
                h, t = get_message_content(part)
                html += h
                text += t
    else:
        data = payload.get('body', {}).get('data')
        if data:
            decoded = base64.urlsafe_b64decode(data).decode('utf-8')
            if payload.get('mimeType') == 'text/html':
                html = decoded
            else:
                text = decoded
                
    return html, text

def get_attachments_metadata(payload):
    """첨부파일 메타데이터 추출"""
    attachments = []
    if 'parts' in payload:
        for part in payload['parts']:
            if 'filename' in part and part['filename']:
                if 'attachmentId' in part['body']:
                    attachments.append({
                        'id': part['body']['attachmentId'],
                        'filename': part['filename'],
                        'size': part['body'].get('size', 0)
                    })
            elif 'parts' in part:
                attachments.extend(get_attachments_metadata(part))
    return attachments

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    client_config = get_google_config()
    if not client_config:
        return "에러: GOOGLE_CREDENTIALS 환경 변수가 설정되지 않았습니다.", 500

    session['keyword'] = request.args.get('keyword', '승인')
    session['days'] = request.args.get('days', '90')

    flow = Flow.from_client_config(client_config, scopes=SCOPES)
    flow.redirect_uri = url_for('callback', _external=True, _scheme='https')
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    state = session.get('state')
    keyword = session.get('keyword', '승인')
    days = int(session.get('days', '90'))
    
    client_config = get_google_config()
    flow = Flow.from_client_config(client_config, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('callback', _external=True, _scheme='https')
    
    flow.fetch_token(authorization_response=request.url)
    
    # Credentials를 JSON 직렬화 가능한 딕셔너리로 변환하여 세션에 저장
    creds = flow.credentials
    session['token'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
    
    results = scrape_now(creds, keyword, days)
    return render_template('index.html', data=results, status='success')

@app.route('/message/<msg_id>')
def get_message_detail(msg_id):
    creds = get_credentials()
    if not creds:
        return abort(401)
    
    service = build('gmail', 'v1', credentials=creds)
    msg = service.users().messages().get(userId='me', id=msg_id).execute()
    
    html, text = get_message_content(msg['payload'])
    attachments = get_attachments_metadata(msg['payload'])
    
    return {
        "html": html,
        "text": text,
        "attachments": attachments
    }

@app.route('/attachment/<msg_id>/<attachment_id>/<filename>')
def download_attachment(msg_id, attachment_id, filename):
    creds = get_credentials()
    if not creds:
        return abort(401)
    
    service = build('gmail', 'v1', credentials=creds)
    attachment = service.users().messages().attachments().get(
        userId='me', messageId=msg_id, id=attachment_id
    ).execute()
    
    file_data = base64.urlsafe_b64decode(attachment['data'])
    return send_file(
        io.BytesIO(file_data),
        download_name=filename,
        as_attachment=True
    )

def scrape_now(creds, keyword, days):
    service = build('gmail', 'v1', credentials=creds)
    start_date = (datetime.now() - timedelta(days=days)).strftime('%Y/%m/%d')
    query = f"after:{start_date} {keyword}"
    
    results = service.users().messages().list(userId='me', q=query, maxResults=10).execute()
    messages = results.get('messages', [])
    
    scraped_results = []
    for msg_info in messages:
        try:
            msg = service.users().messages().get(userId='me', id=msg_info['id']).execute()
            headers = msg['payload']['headers']
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '제목 없음')
            date = next((h['value'] for h in headers if h['name'] == 'Date'), '날짜 없음')
            
            # 본문 추출 (추출 알고리즘 개선)
            html, text = get_message_content(msg['payload'])
            body = text if text else html
            
            match = re.search(r'(승인번호|금액|결제액)[:\s]*([^\n\r]+)', body)
            extracted_info = match.group(0) if match else "상세 정보 없음"

            scraped_results.append({
                "id": msg['id'],
                "threadId": msg['threadId'],
                "date": date, 
                "subject": subject,
                "extracted_price": extracted_info, 
                "snippet": msg.get('snippet'),
                "has_attachments": len(get_attachments_metadata(msg['payload'])) > 0
            })
        except Exception as e:
            print(f"Error processing message {msg_info['id']}: {e}")
            continue
    return scraped_results

if __name__ == '__main__':
    app.run(port=5000)
