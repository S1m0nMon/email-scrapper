import os
import json
import base64
import re
from datetime import datetime, timedelta
from flask import Flask, redirect, url_for, session, request, render_template
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

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

def get_message_body(payload):
    """메일 본문 추출 헬퍼 함수"""
    body = ""
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                data = part['body'].get('data')
                if data: body += base64.urlsafe_b64decode(data).decode('utf-8')
            elif 'parts' in part: body += get_message_body(part)
    else:
        data = payload.get('body', {}).get('data')
        if data: body = base64.urlsafe_b64decode(data).decode('utf-8')
    return body

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    client_config = get_google_config()
    if not client_config:
        return "에러: GOOGLE_CREDENTIALS 환경 변수가 설정되지 않았습니다.", 500

    # 파일 대신 client_config(딕셔너리)를 사용합니다.
    flow = Flow.from_client_config(client_config, scopes=SCOPES)
    
    # Vercel에서는 https를 강제해야 할 수도 있습니다.
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
    client_config = get_google_config()
    flow = Flow.from_client_config(client_config, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('callback', _external=True, _scheme='https')
    
    flow.fetch_token(authorization_response=request.url)
    results = scrape_now(flow.credentials)
    return render_template('index.html', data=results, status='success')

def scrape_now(creds):
    service = build('gmail', 'v1', credentials=creds)
    three_months_ago = (datetime.now() - timedelta(days=90)).strftime('%Y/%m/%d')
    query = f"after:{three_months_ago} 승인"
    
    results = service.users().messages().list(userId='me', q=query, maxResults=10).execute()
    messages = results.get('messages', [])
    
    scraped_results = []
    for msg_info in messages:
        try:
            msg = service.users().messages().get(userId='me', id=msg_info['id']).execute()
            headers = msg['payload']['headers']
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '제목 없음')
            date = next((h['value'] for h in headers if h['name'] == 'Date'), '날짜 없음')
            body = get_message_body(msg['payload'])
            
            match = re.search(r'(승인번호|금액|결제액)[:\s]*([^\n\r]+)', body)
            extracted_info = match.group(0) if match else "상세 정보 없음"

            scraped_results.append({
                "date": date, "subject": subject,
                "extracted_price": extracted_info, "snippet": msg.get('snippet')
            })
        except: continue
    return scraped_results

if __name__ == '__main__':
    app.run(port=5000)