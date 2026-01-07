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
    """환경 변수 또는 파일에서 구글 설정 JSON을 읽어옵니다."""
    raw_config = os.environ.get("GOOGLE_CREDENTIALS")
    if raw_config:
        try:
            return json.loads(raw_config)
        except json.JSONDecodeError:
            pass
            
    # 로컬 개발을 위한 파일 폴백 (api/client_secret.json)
    config_path = os.path.join(os.path.dirname(__file__), 'client_secret.json')
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
            
    return None

from google.auth.transport.requests import Request

def get_credentials():
    token_info = session.get('token')
    if not token_info:
        return None
    
    creds = Credentials.from_authorized_user_info(token_info, SCOPES)
    
    # 토큰이 만료되었다면 갱신 시도
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        # 업데이트된 토큰 정보를 다시 세션에 저장
        session['token']['token'] = creds.token
        session.modified = True 
        
    return creds

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
    if 'token' in session:
        return render_template('index.html', view='results')
    return redirect(url_for('intro'))

@app.route('/intro')
def intro():
    return render_template('index.html', view='intro')

@app.route('/login')
def login():
    client_config = get_google_config()
    if not client_config:
        return "에러: GOOGLE_CREDENTIALS 환경 변수가 설정되지 않았습니다.", 500

    # 파라미터가 없으면 기본값 사용
    session['keyword'] = request.args.get('keyword', '승인')
    session['days'] = request.args.get('days', '90')

    flow = Flow.from_client_config(client_config, scopes=SCOPES)
    
    # 로컬 개발 환경(localhost)인 경우 http 허용
    if request.host.startswith('localhost') or request.host.startswith('127.0.0.1'):
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        flow.redirect_uri = url_for('callback', _external=True)
    else:
        flow.redirect_uri = url_for('callback', _external=True, _scheme='https')
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
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
    
    if request.host.startswith('localhost') or request.host.startswith('127.0.0.1'):
        flow.redirect_uri = url_for('callback', _external=True)
    else:
        flow.redirect_uri = url_for('callback', _external=True, _scheme='https')
    
    flow.fetch_token(authorization_response=request.url)
    
    # Credentials를 JSON 직렬화 가능한 딕셔너리로 변환하여 세션에 저장
    creds = flow.credentials
    
    # 클라이언트 설정에서 필요한 정보 추출
    web_config = client_config.get('web', {})
    
    session['token'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': web_config.get('token_uri'),
        'client_id': web_config.get('client_id'),
        'client_secret': web_config.get('client_secret'),
        'scopes': creds.scopes
    }
    
    results = scrape_now(creds, keyword, days)
    return render_template('index.html', data=results, status='success')

@app.route('/message/<msg_id>')
def get_message_detail(msg_id):
    try:
        creds = get_credentials()
        if not creds:
            print("Error: No credentials found in session")
            return {"error": "로그인 세션이 만료되었습니다. 다시 로그인해주세요."}, 401
        
        service = build('gmail', 'v1', credentials=creds)
        msg = service.users().messages().get(userId='me', id=msg_id).execute()
        
        html, text = get_message_content(msg['payload'])
        attachments = get_attachments_metadata(msg['payload'])
        
        return {
            "html": html,
            "text": text,
            "attachments": attachments
        }
    except Exception as e:
        print(f"Error fetching message {msg_id}: {str(e)}")
        return {"error": f"메시지를 불러오는 중 오류가 발생했습니다: {str(e)}"}, 500

@app.route('/attachment/<msg_id>/<attachment_id>/<filename>')
def download_attachment(msg_id, attachment_id, filename):
    try:
        creds = get_credentials()
        if not creds:
            return "로그인이 필요합니다.", 401
        
        service = build('gmail', 'v1', credentials=creds)
        
        # 1. 첨부파일 데이터 가져오기
        attachment = service.users().messages().attachments().get(
            userId='me', messageId=msg_id, id=attachment_id
        ).execute()
        
        if 'data' not in attachment:
            return "파일 데이터를 찾을 수 없습니다.", 404

        # 2. Base64 디코딩
        file_data = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
        
        # [참고] Vercel 무료 플랜은 응답 크기가 약 4.5MB로 제한됩니다.
        if len(file_data) > 4 * 1024 * 1024:
            return "Vercel 제한으로 인해 4MB 이상의 파일은 다운로드할 수 없습니다.", 413

        return send_file(
            io.BytesIO(file_data),
            download_name=filename,
            as_attachment=True,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        # 에러 발생 시 Vercel Logs에 기록
        print(f"!!! Attachment Error: {str(e)}")
        return f"서버 에러: {str(e)}", 500

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
