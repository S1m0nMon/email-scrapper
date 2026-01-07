import os
import base64
import re
from datetime import datetime, timedelta
from flask import Flask, redirect, url_for, session, request, render_template
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

# Vercel 환경에서 템플릿 폴더 위치 지정 (api 폴더 외부의 templates 폴더 참조)
app = Flask(__name__, template_folder='../templates')
app.secret_key = os.environ.get("SECRET_KEY", "temporary_secret_key_12345")
app.config['JSON_AS_ASCII'] = False

# 로컬 테스트 시에만 필요 (Vercel 배포 시에는 자동으로 HTTPS가 적용되므로 무시됨)
if os.environ.get('VERCEL') != '1':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# 구글 콘솔에서 다운로드한 파일명
CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_message_body(payload):
    """Gmail 메일 페이로드에서 텍스트 본문 추출"""
    body = ""
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                data = part['body'].get('data')
                if data:
                    body += base64.urlsafe_b64decode(data).decode('utf-8')
            elif 'parts' in part:
                body += get_message_body(part)
    else:
        data = payload.get('body', {}).get('data')
        if data:
            body = base64.urlsafe_b64decode(data).decode('utf-8')
    return body

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    # Flow 객체 생성 시 redirect_uri를 동적으로 생성
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = url_for('callback', _external=True)
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    state = session.get('state')
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('callback', _external=True)
    
    # 구글이 보낸 코드를 토큰으로 교환
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    
    # 스크래핑 실행
    results = scrape_now(flow.credentials)
    return render_template('index.html', data=results, status='success')

def scrape_now(creds):
    service = build('gmail', 'v1', credentials=creds)
    
    # 3개월 전 날짜 및 키워드 설정
    three_months_ago = (datetime.now() - timedelta(days=90)).strftime('%Y/%m/%d')
    query = f"after:{three_months_ago} 승인"
    
    # 최근 10개 메일 목록 가져오기
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
            
            # 정규표현식: 승인번호나 금액 패턴 추출 (필요에 따라 수정)
            match = re.search(r'(승인번호|금액|결제액)[:\s]*([^\n\r]+)', body)
            extracted_info = match.group(0) if match else "상세 정보 없음"

            scraped_results.append({
                "date": date,
                "subject": subject,
                "extracted_price": extracted_info,
                "snippet": msg.get('snippet')
            })
        except Exception:
            continue
            
    return scraped_results

# Vercel은 이 객체를 호출하여 실행함
# 로컬 테스트용 실행부
if __name__ == '__main__':
    app.run(port=5000, debug=True)