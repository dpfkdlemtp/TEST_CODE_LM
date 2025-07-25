# streamlit run lovemateV2.py

# run_multi_matching 함수 시트 변경 필요
# tab3의 시트 도 변경 필요

from urllib.parse import urlparse, parse_qs
import urllib
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from oauth2client.service_account import ServiceAccountCredentials
from mWTP import create_watermark, add_watermark_to_pdf
from urllib.request import urlretrieve
from cryptography.fernet import Fernet
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import io
import base64
import json
from googleapiclient.http import MediaFileUpload
import os
import time
import streamlit as st
import pandas as pd
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from PIL import Image
import requests
from mPC import create_pdf_from_data
import tempfile
from datetime import datetime
import inspect
from streamlit_oauth import OAuth2Component
import streamlit as st
import google.auth.transport.requests
import google.oauth2.id_token
import requests
import pandas as pd
from datetime import datetime
from urllib.parse import urlencode
from urllib.parse import urlparse, parse_qs
import pytz

st.set_page_config(page_title="회원 매칭 시스템", layout="wide")

params = dict(st.query_params)
trigger = params.get("trigger", [None])
token = params.get("token", [None])
sheet_name = params.get("sheet_name", [None])  # 기본값 설정

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["회원 매칭", "발송 필요 회원", "사진 보기", "작업자 메모장", "회원 메모장", "프로필카드 생성"])


# # ✅ 세션 기본 설정 (로그인 생략용 테스트)
# if "logged_in" not in st.session_state:
#     # 테스트용 자동 로그인 활성화
#     st.session_state["logged_in"] = True
#     st.session_state["user_id"] = "TEST"
#
# # # ✅ 세션 기본 설정
# # if "logged_in" not in st.session_state:
# #     st.session_state["logged_in"] = False
# # if "user_id" not in st.session_state:
# #     st.session_state["user_id"] = ""

# Streamlit App 전용
def load_google_service_account_key():
    return st.secrets["gcp"]


# Streamlit 콘솔 로그 출력용 (브라우저 개발자 도구에서 확인 가능)
def js_console_log(message):
    st.markdown(
        f"<script>console.log('[Streamlit JS] {message}');</script>",
        unsafe_allow_html=True
    )


# 🔒 암복호화용 키 로딩 (키정보 시트 B1)
@st.cache_resource(show_spinner=False)
@st.cache_resource(ttl=300, show_spinner=False)
def load_sheet_with_ws(sheet_name):
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    key_dict = load_google_service_account_key()
    creds = ServiceAccountCredentials.from_json_keyfile_dict(key_dict, scope)
    client = gspread.authorize(creds)

    # ✅ 링크는 load_sheet와 동일한 두 번째 문서
    sheet = client.open_by_url(
        "https://docs.google.com/spreadsheets/d/1jnZqqmZB8zWau6CHqxm-L9fxlXDaWxOaJm6uDcE6WN0/edit")
    worksheet = sheet.worksheet(sheet_name)
    raw_values = worksheet.get_all_values()
    header = raw_values[1]
    data = raw_values[2:]
    df = pd.DataFrame(data, columns=header)
    return df, worksheet


def load_secret_key():
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    creds = ServiceAccountCredentials.from_json_keyfile_dict(load_google_service_account_key(), scope)
    client = gspread.authorize(creds)

    sheet = client.open_by_url(
        "https://docs.google.com/spreadsheets/d/1XwEk_TifWuCkOjjUuJ0kMFYy0dKxV46XvQ_rgts2kL8/edit")
    ws = sheet.worksheet("키정보")
    key = ws.acell('B1').value
    return key.encode()


# 🔒 비밀번호 암호화
def encrypt_password(password):
    fernet = Fernet(load_secret_key())
    return fernet.encrypt(password.encode()).decode()


# 🔓 비밀번호 복호화
def decrypt_password(encrypted_password):
    fernet = Fernet(load_secret_key())
    return fernet.decrypt(encrypted_password.encode()).decode()


# ✅ 구글 관리자 스프레드시트 연결
def connect_sheet(sheet_name):
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    creds = ServiceAccountCredentials.from_json_keyfile_dict(load_google_service_account_key(), scope)
    client = gspread.authorize(creds)
    sheet = client.open_by_url(
        "https://docs.google.com/spreadsheets/d/1XwEk_TifWuCkOjjUuJ0kMFYy0dKxV46XvQ_rgts2kL8/edit")
    worksheet = sheet.worksheet(sheet_name)

    try:
        data = worksheet.get_all_records()
        df = pd.DataFrame(data)
        df.columns = [str(col).strip() for col in df.columns]

    except Exception as e:
        st.error(f"❌ [{sheet_name}] 시트 연결 중 오류 발생: {e}")
        write_log("", f"❌ [{sheet_name}] 시트 연결 중 오류 발생: {e}")
        df = pd.DataFrame()  # 비어있는 DataFrame 리턴 (에러 방지)

    return df, worksheet


import inspect


def write_log(member_id: str = "", message: str = ""):
    try:
        # ✅ LoginID: 로그인된 세션에서 가져오되 없으면 "AppsScript"
        login_id = st.session_state.get("user_id", "")

        # ✅ Action: 호출한 함수명 자동 감지
        frame = inspect.currentframe()
        outer_frame = inspect.getouterframes(frame)[1]
        action = outer_frame.function

        # ✅ Timestamp
        kst = pytz.timezone("Asia/Seoul")
        now = datetime.now(kst).strftime("%Y-%m-%d %H:%M:%S")

        # ✅ Google Sheet에 기록
        _, ws = connect_sheet("로그")
        row = [now, login_id, member_id, action, message]
        ws.append_row(row)
    except Exception as e:
        print(f"[로그 기록 실패] {e}")


write_log("", f"📩 트리거 요청 감지 : trigger={trigger}, token={token}, sheet_name={sheet_name}")


def create_account_sheet():
    # 구글 인증 범위
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]

    # 서비스 계정 키 로딩 (Streamlit에서는 st.secrets 사용)
    key_dict = st.secrets["gcp"]  # 또는 JSON 파일에서 로딩: json.load(open("your-service-key.json"))
    creds = ServiceAccountCredentials.from_json_keyfile_dict(key_dict, scope)
    client = gspread.authorize(creds)

    # 📌 스프레드시트 열기 (관리자용 시트 URL 사용)
    sheet = client.open_by_url(
        "https://docs.google.com/spreadsheets/d/1XwEk_TifWuCkOjjUuJ0kMFYy0dKxV46XvQ_rgts2kL8/edit")

    # ✅ 시트가 이미 존재하는지 확인하고 없으면 생성
    sheet_name = "계정정보"
    try:
        worksheet = sheet.worksheet(sheet_name)
        print(f"✅ 시트 '{sheet_name}'이 이미 존재합니다.")
    except gspread.exceptions.WorksheetNotFound:
        worksheet = sheet.add_worksheet(title=sheet_name, rows="100", cols="3")
        worksheet.update("A1:C1", [["이메일", "PW", "마지막 로그인 시간"]])
        print(f"🆕 시트 '{sheet_name}'이 새로 생성되었습니다.")

    return worksheet


def signup(new_id, new_pw):
    df_accounts, ws_accounts = connect_sheet("계정정보")
    df_memo, ws_memo = connect_sheet("메모")
    df_log, ws_log = connect_sheet("로그인기록")

    # ✅ 계정정보 시트가 비어있거나 헤더가 없는 경우 → 초기화
    if df_accounts.empty or "ID" not in df_accounts.columns:
        ws_accounts.update("A1:C1", [["이메일", "PW", "마지막 로그인 시간"]])
        df_accounts = pd.DataFrame(columns=["이메일", "PW", "마지막 로그인 시간"])
        st.warning("⚠️ 계정정보 시트가 비어 있어 자동 초기화되었습니다. 다시 시도해주세요.")
        return False, "⚠️ 시트를 초기화했어요. 다시 회원가입을 시도해주세요."

    # ID 중복 체크
    if new_id in df_accounts["이메일"].values:
        return False, "❌ 이미 존재하는 ID입니다."

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    encrypted_pw = encrypt_password(new_pw)

    # 1. 계정정보 추가
    new_account_row = [new_id, encrypted_pw, now_str]
    ws_accounts.append_row(new_account_row)

    # 2. 메모 시트 추가
    new_memo_row = [new_id, "", now_str]
    if df_memo.empty:
        ws_memo.update('A2', [["이메일", "메모", "저장 시간"]])
    ws_memo.append_row(new_memo_row)

    # 3. 로그인 기록 시트 추가
    new_log_row = [new_id, now_str]
    if df_log.empty:
        ws_log.update('A2', [["이메일", "로그인 시간"]])
    ws_log.append_row(new_log_row)

    return True, "✅ 회원가입 완료!"


# ✅ 로그인 함수
def login(user_id, user_pw):
    df_accounts, ws_accounts = connect_sheet("계정정보")
    df_log, ws_log = connect_sheet("로그인기록")

    user = df_accounts[df_accounts["이메일"] == user_id]
    if not user.empty:
        try:
            decrypted_pw = decrypt_password(user.iloc[0]["PW"])
            if decrypted_pw == user_pw:
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # 마지막 로그인 시간 업데이트
                row_idx = user.index[0] + 2
                ws_accounts.update_cell(row_idx, 3, now_str)

                # 로그인 기록 추가
                try:
                    next_seq = len(df_log) + 1  # 현재 데이터 수 + 1
                    new_log_row = [next_seq, user_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
                    ws_log.append_row(new_log_row)
                except Exception as e:
                    st.error(f"로그인 기록 저장 실패: {e}")
                    write_log("", f"로그인 기록 저장 실패: {e}")

                return True
            else:
                return False
        except Exception:
            return False
    else:
        return False


CLIENT_ID = st.secrets["google"]["client_id"]
REDIRECT_URI = "https://lovematev2.streamlit.app"
AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "user_id" not in st.session_state:
    st.session_state["user_id"] = ""


# # ✅ Google 서비스 계정 키 로딩 함수
# def load_google_service_account_key():
#     with open("lovemateV2.json", "r") as f:
#         key_dict = json.load(f)
#     return key_dict

# ✅ load_sheet 함수에 캐시 적용
@st.cache_data(ttl=300, show_spinner=False)
def load_sheet(sheet_name):
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    key_dict = load_google_service_account_key()
    creds = ServiceAccountCredentials.from_json_keyfile_dict(key_dict, scope)
    client = gspread.authorize(creds)
    sheet = client.open_by_url(
        "https://docs.google.com/spreadsheets/d/1jnZqqmZB8zWau6CHqxm-L9fxlXDaWxOaJm6uDcE6WN0/edit")
    worksheet = sheet.worksheet(sheet_name)
    raw_values = worksheet.get_all_values()
    header = raw_values[1]
    data = raw_values[2:]
    df = pd.DataFrame(data, columns=header)
    return df


# ✅ Google Drive 연결 함수
@st.cache_resource(ttl=3000, show_spinner=False)
def get_drive_service():
    scope = ['https://www.googleapis.com/auth/drive']
    key_dict = load_google_service_account_key()
    creds = ServiceAccountCredentials.from_json_keyfile_dict(key_dict, scope)
    return build('drive', 'v3', credentials=creds)


# --- 업로드 함수 (캐시 없음) ---
def upload_image_to_drive(image_file, file_name, original_file_id=None):
    service = get_drive_service()
    folder_id = "1JHZqpAY50x-vhala9Ou3MDW3l2PfOu5k9jPzIflqWzqUEsAnwzLMfJiH3px5ftorgsfnnu2h"

    file_metadata = {
        'name': file_name,
        'parents': [folder_id],
    }
    media = MediaFileUpload(image_file, mimetype='image/jpeg')
    file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id',
        supportsAllDrives=True
    ).execute()

    # 권한 복사 실행
    if original_file_id:
        copy_drive_permissions(original_file_id, file['id'])
    else:
        set_drive_public_permission(file['id'])

    return file['id']


# --- 권한 복사 함수 (캐시 O) ---
@st.cache_data(ttl=3600, show_spinner=False)
def copy_drive_permissions(source_file_id, target_file_id):
    service = get_drive_service()
    permissions = service.permissions().list(
        fileId=source_file_id,
        fields='permissions(id,type,role,emailAddress)'
    ).execute().get('permissions', [])

    for perm in permissions:
        if perm['type'] in ['anyone', 'domain', 'user', 'group', 'owner']:
            body = {
                'type': perm['type'],
                'role': perm['role'],
            }
            if perm['type'] in ['user', 'group'] and 'emailAddress' in perm:
                body['emailAddress'] = perm['emailAddress']
            if perm['role'] == 'owner':
                body['role'] = 'writer'  # owner → writer로 강등

            try:
                service.permissions().create(
                    fileId=target_file_id,
                    body=body,
                    sendNotificationEmail=False,
                    supportsAllDrives=True
                ).execute()
            except Exception:
                write_log("", "드라이브 권한 복사 오류")
                pass


# --- 퍼블릭 권한 세팅 함수 (캐시 X) ---
def set_drive_public_permission(file_id):
    service = get_drive_service()
    service.permissions().create(
        fileId=file_id,
        body={'type': 'anyone', 'role': 'reader'},
        supportsAllDrives=True
    ).execute()


# --- 시트 업데이트 함수 ---
def update_profile_photo_in_sheet(member_id, photo_index, new_url):
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    key_dict = load_google_service_account_key()
    creds = ServiceAccountCredentials.from_json_keyfile_dict(key_dict, scope)
    client = gspread.authorize(creds)
    sheet = client.open_by_url(
        "https://docs.google.com/spreadsheets/d/1jnZqqmZB8zWau6CHqxm-L9fxlXDaWxOaJm6uDcE6WN0/edit")
    worksheet = sheet.worksheet("프로필")
    all_values = worksheet.get_all_values()
    headers = all_values[1]  # 2행: 헤더
    data_rows = all_values[2:]  # 3행부터: 데이터

    for idx, row in enumerate(data_rows):
        record = dict(zip(headers, row))
        if str(record.get("회원 ID", "")).strip() == str(member_id).strip():
            current_photos = str(record.get("본인 사진", "")).split(",")
            if len(current_photos) <= photo_index:
                current_photos += [""] * (photo_index - len(current_photos) + 1)
            current_photos[photo_index] = new_url
            update_row = idx + 3  # 실제 시트 행 번호
            update_col = headers.index("본인 사진") + 1  # 열 번호
            worksheet.update_cell(update_row, update_col, ",".join(current_photos))
            return True
    return False


def get_latest_profile_photo(member_id):
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    key_dict = load_google_service_account_key()
    creds = ServiceAccountCredentials.from_json_keyfile_dict(key_dict, scope)
    client = gspread.authorize(creds)
    sheet = client.open_by_url(
        "https://docs.google.com/spreadsheets/d/1jnZqqmZB8zWau6CHqxm-L9fxlXDaWxOaJm6uDcE6WN0/edit")
    worksheet = sheet.worksheet("프로필")

    all_values = worksheet.get_all_values()
    headers = all_values[1]  # 두 번째 줄이 헤더
    data_rows = all_values[2:]  # 세 번째 줄부터 데이터

    # 헤더에서 '회원 ID'와 '본인 사진' 인덱스 찾기
    id_index = headers.index("회원 ID")
    photo_index = headers.index("본인 사진")

    for row in data_rows:
        if str(row[id_index]).strip() == str(member_id).strip():
            return str(row[photo_index]).split(",")

    return []


def image_to_base64(img):
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_b64 = base64.b64encode(buffered.getvalue()).decode()
    return img_b64


@st.cache_data(ttl=300, show_spinner=False)
def get_drive_image(file_id):
    service = get_drive_service()
    request = service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    fh.seek(0)
    image = Image.open(fh)
    image.thumbnail((200, 200))  # 크기 축소
    return image


def get_drive_image_profilecard(file_id):
    service = get_drive_service()
    request = service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    fh.seek(0)
    return Image.open(fh)  # 👈 썸네일 처리 없이 원본 이미지 반환


@st.cache_data(ttl=300, show_spinner=False)
def get_drive_image2(file_id):
    service = get_drive_service()
    request = service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    fh.seek(0)
    image = Image.open(fh)
    image.thumbnail((300, 300))  # 크기 축소
    return image


# Google Drive 공유 URL에서 파일 ID 추출
def extract_drive_file_id(url):
    if "id=" in url:
        return url.split("id=")[-1].split("&")[0]
    elif "/file/d/" in url:
        return url.split("/file/d/")[-1].split("/")[0]
    return ""


def upload_file_to_drive(file_path, filename, folder_id):
    scopes = ['https://www.googleapis.com/auth/drive']
    key_dict = load_google_service_account_key()
    creds = ServiceAccountCredentials.from_json_keyfile_dict(key_dict, scopes)
    service = build('drive', 'v3', credentials=creds)

    # 🔍 Step 1: 기존 동일 파일명 검색
    query = f"'{folder_id}' in parents and name = '{filename}' and trashed = false"
    response = service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
    files = response.get('files', [])

    media = MediaFileUpload(file_path, resumable=True)

    if files:
        file_id = files[0]['id']
        print(f"♻ 기존 파일 덮어쓰기: {filename}")
        updated = service.files().update(
            fileId=file_id,
            media_body=media
        ).execute()
        return updated['id']
    else:
        print(f"🆕 새 파일 업로드: {filename}")
        file_metadata = {'name': filename, 'parents': [folder_id]}
        uploaded = service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()
        return uploaded['id']

def download_pdf_from_drive(file_id, output_path):
    scopes = ['https://www.googleapis.com/auth/drive.readonly']
    key_dict = load_google_service_account_key()
    creds = ServiceAccountCredentials.from_json_keyfile_dict(key_dict, scopes)
    service = build('drive', 'v3', credentials=creds)

    request = service.files().get_media(fileId=file_id)
    fh = io.FileIO(output_path, mode='wb')
    downloader = MediaIoBaseDownload(fh, request)

    done = False
    while not done:
        status, done = downloader.next_chunk()

def generate_profile_card_from_sheet(member_id: str):
    member_df = load_sheet("회원")
    profile_df = load_sheet("프로필")

    write_log(member_id, f"[디버그] 시트 로딩 완료: 회원 {len(member_df)}명, 프로필 {len(profile_df)}명")

    member_data = member_df[member_df["회원 ID"] == member_id]
    profile_data = profile_df[profile_df["회원 ID"] == member_id]

    if member_data.empty or profile_data.empty:
        write_log(member_id, f"[❌에러] {member_id}에 해당하는 정보가 시트에 없습니다.")
        raise ValueError(f"{member_id}에 해당하는 회원 정보 또는 프로필 정보가 없습니다.")

    m = member_data.iloc[0].to_dict()
    p = profile_data.iloc[0].to_dict()

    # 사진 다운로드 또는 경로 설정 (Streamlit 서버에 미리 저장된 경로로 매핑하거나 다운로드 구현 필요)
    # 임시방식: 사진1~4는 temp에 다운로드했다고 가정
    photo_urls = str(p.get("본인 사진", "")).split(",")[:4]
    photo_paths = []

    write_log(member_id, f"[디버그] 📸 사진 링크 수집됨: {photo_urls}")

    for i, url in enumerate(photo_urls):
        try:
            file_id = extract_drive_file_id(url.strip())
            image = get_drive_image_profilecard(file_id)
            temp_img = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
            image.save(temp_img.name)
            photo_paths.append(temp_img.name)
            write_log(member_id, f"[디버그] ✅ 이미지 {i + 1} 저장: {temp_img.name}")
        except Exception as e:
            write_log(member_id, f"[⚠️사진 에러] {url} 처리 실패: {e}")
            continue

    data = {
        "member_code": member_id,
        "age": m.get("본인(나이)", ""),
        "height": m.get("본인(키)", ""),
        "region": p.get("본인(거주지 - 시구)", ""),
        "smoking": m.get("본인(흡연)", ""),
        "drink": m.get("본인(음주)", ""),
        "edu": m.get("본인(학력)", ""),
        "company": m.get("본인(회사 규모)", ""),
        "work": m.get("본인(근무 형태)", ""),
        "religion": m.get("본인(종교)", ""),
        "mbti": p.get("MBTI", ""),
        "job": p.get("본인(직무)", ""),
        "salary": p.get("본인(연봉)", ""),
        "car": p.get("본인(자차)", ""),
        "house": p.get("본인(자가)", ""),
        "info_text": p.get("소개", ""),
        "attract_text": p.get("매력", ""),
        "hobby_text": p.get("취미", ""),
        "dating_text": p.get("연애스타일", ""),
        "photo_paths": photo_paths,
    }

    # 🔽 뱃지 필드 처리
    badge_text = str(p.get("인증 뱃지", "")).lower()

    data.update({
        "verify_income": "고소득" in badge_text,
        "verify_job": any(x in badge_text for x in ["전문직", "대기업", "사업가"]),
        "verify_house": "부동산" in badge_text,
        "verify_edu": "고학력" in badge_text,
        "verify_car": any(x in badge_text for x in ["자동차", "자차"]),
        "verify_asset": "자산" in badge_text
    })

    write_log(member_id, f"[디버그] 🧾 PDF 생성 시작 {data}")
    output_path = create_pdf_from_data(data)
    write_log(member_id, f"[디버그] 📄 PDF 생성 완료: {output_path}")

    write_log(member_id, f"[디버그] ☁️ Drive 업로드 시작")
    uploaded_id = upload_file_to_drive(
        output_path,
        f"{member_id}_프로필카드.pdf",
        folder_id="104l4k5PPO25thz919Gi4241_IQ_MSsfe"
    )

    write_log(member_id, f"[디버그] ✅ 업로드 완료: 파일 ID {uploaded_id}")

    # ✅ 프로필카드 링크 생성
    pdf_url = f"https://drive.google.com/file/d/{uploaded_id}/view?usp=sharing"

    # ✅ 프로필 시트의 AY열에 링크 업데이트
    try:
        scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
        key_dict = load_google_service_account_key()
        creds = ServiceAccountCredentials.from_json_keyfile_dict(key_dict, scope)
        client = gspread.authorize(creds)

        sheet = client.open_by_url(
            "https://docs.google.com/spreadsheets/d/1jnZqqmZB8zWau6CHqxm-L9fxlXDaWxOaJm6uDcE6WN0/edit")
        worksheet = sheet.worksheet("프로필")
        all_values = worksheet.get_all_values()
        headers = all_values[1]  # 2행이 헤더
        data_rows = all_values[2:]  # 3행부터 데이터

        for idx, row in enumerate(data_rows):
            if str(row[headers.index("회원 ID")]).strip() == str(member_id).strip():
                row_num = idx + 3  # 실제 시트 행 번호
                col_num = headers.index("프로필 카드") + 1 if "프로필 카드" in headers else 52  # AY열 기본값
                worksheet.update_cell(row_num, col_num, pdf_url)
                write_log(member_id, f"✅ 프로필카드 링크 저장 완료: {pdf_url}")
                break
    except Exception as e:
        write_log(member_id, f"❌ 프로필카드 링크 저장 실패: {e}")

    return uploaded_id


# ---------------------------
# 매칭 로직
# ---------------------------

def match_members(df, match_data):
    target_df = df[df["회원 ID"] == match_data["memberId"]]
    if target_df.empty:
        st.warning("입력한 회원 ID에 해당하는 회원이 없습니다.")
        return pd.DataFrame()

    target = target_df.iloc[0]
    filtered = df.copy()

    numeric_fields = ["상태 FLAG", "본인(키)", "본인(나이)"]
    for field in numeric_fields:
        filtered[field] = pd.to_numeric(filtered[field], errors="coerce")

    filtered = filtered[
        (filtered["성별"] != target["성별"]) &
        (filtered["상태 FLAG"] >= 4) &
        (~filtered["매칭권"].fillna("").str.contains("시크릿"))
        ]
    print(f"1차 필터링 후 인원: {filtered}")

    # 채널 필터
    if match_data["channel"] and match_data["channel"] != ["전체"]:
        valid_channels = []
        channel_map = {"프립(F)": "F", "네이버(N)": "N", "프사오(O)": "O", "인스타(A)": "A", "기타(B)": "B", "기타2(C)": "C"}
        for ch in match_data["channel"]:
            if ch in channel_map:
                valid_channels.append(channel_map[ch])
        filtered = filtered[filtered["주문번호"].astype(str).str[0].isin(valid_channels)]
    print(f"채널 필터링 후 인원: {filtered}")

    if match_data["faces"]:
        filtered = filtered[filtered["등급(외모)"].isin(match_data["faces"])]
        print(f"등급(외모) 필터링 후 인원: {filtered}")

    if match_data["abilitys"]:
        filtered = filtered[filtered["등급(능력)"].isin(match_data["abilitys"])]
        print(f"등급(능력) 필터링 후 인원: {filtered}")

    if match_data["faceShape"] and match_data["faceShape"] != ["전체"]:
        filtered = filtered[filtered["본인(외모)"].isin(match_data["faceShape"])]
        print(f"얼굴상 필터링 후 인원: {filtered}")
    cond = match_data["conditions"]
    try:
        if cond[0]:
            min_h, max_h = sorted(map(int, str(target["이상형(키)"]).replace(" ", "").split("~")))
            filtered = filtered[filtered["본인(키)"].between(min_h, max_h)]
            print(f"키 필터링 후 인원: {filtered}")
    except:
        write_log(match_data["memberId"], "키 필터 오류")
        pass

    try:
        if cond[1]:
            min_y, max_y = sorted(map(int, str(target["이상형(나이)"]).replace(" ", "").split("~")))
            filtered = filtered[filtered["본인(나이)"].between(min_y, max_y)]
            print(f"나이 필터링 후 인원: {filtered}")
    except Exception as e:
        print(f"[나이 필터 에러] {e}")
        write_log(match_data["memberId"], "나이 필터 오류")

    condition_fields = [
        "이상형(사는 곳)", "이상형(학력)", "이상형(흡연)", "이상형(종교)",
        "이상형(회사 규모)", "이상형(근무 형태)", "이상형(음주)", "이상형(문신)"
    ]
    profile_fields = [
        "본인(거주지-분류)", "본인(학력)", "본인(흡연)", "본인(종교)",
        "본인(회사 규모)", "본인(근무 형태)", "본인(음주)", "본인(문신)"
    ]

    for i in range(2, 10):
        if cond[i]:
            ideals_raw = str(target.get(condition_fields[i - 2], ""))
            if ideals_raw.strip():
                ideals = set(map(str.strip, ideals_raw.split(',')))
                filtered = filtered[filtered[profile_fields[i - 2]].isin(ideals)]
                print(f"{profile_fields[i - 2]} 기준 {ideals} 필터링 후 인원: {filtered}")
            else:
                print(f"{profile_fields[i - 2]} 조건 비어있음 → 필터 생략")

    if match_data["afterDate"]:
        try:
            after_date = pd.to_datetime(match_data["afterDate"])
            filtered["설문 날짜"] = pd.to_datetime(filtered["설문 날짜"], errors="coerce")
            filtered = filtered[filtered["설문 날짜"] >= after_date]
            print(f"날짜 필터링 후 인원: {filtered}")
        except:
            write_log(match_data["memberId"], "날짜 필터링 오류")
            pass

    sent_ids = str(target.get("받은 프로필 목록", "")).split(",") if pd.notna(target.get("받은 프로필 목록")) else []
    sent_ids_set = set(map(str.strip, sent_ids))
    filtered = filtered[~filtered["회원 ID"].astype(str).isin(sent_ids_set)]
    print(f"받은 프로필 필터링 후 인원: {filtered}")

    return filtered


def get_profile_candidates(member_id, channel, faces, condition_list, member_df):
    match_data = {
        "memberId": member_id,
        "channel": channel,
        "conditions": condition_list,
        "faces":faces
    }
    return auto_match_members(member_df, match_data)


def get_weighted_top4_ids(df):
    if df.empty:
        return []
    score_values = df["보내진 횟수"].fillna(0).astype(float)
    weights = 1 / (score_values + 1)
    if weights.sum() > 0:
        return df.sample(n=min(4, len(df)), weights=weights, random_state=42)["회원 ID"].tolist()
    else:
        return df.head(4)["회원 ID"].tolist()

def get_custom_face_top4(df, my_face_grade):
    face_column = "등급(외모)"
    df[face_column] = df[face_column].astype(str).str.strip()
    selected_ids = []

    def weighted_sample(group_df, n):
        if group_df.empty:
            return []
        weights = 1 / (group_df["보내진 횟수"].fillna(0).astype(float) + 1)
        return group_df.sample(n=min(n, len(group_df)), weights=weights, random_state=42)["회원 ID"].tolist()

    if my_face_grade == "상":
        selected_ids += weighted_sample(df[df[face_column] == "상"], 2)
        mid_df = df[df[face_column].isin(["중상", "중"])]
        selected_ids += weighted_sample(mid_df, 2)

    elif my_face_grade in ["중상", "중"]:
        selected_ids += weighted_sample(df[df[face_column] == "상"], 1)
        mid_df = df[df[face_column].isin(["중상", "중"])]
        selected_ids += weighted_sample(mid_df, 3)

    elif my_face_grade == "중하":
        selected_ids += weighted_sample(df[df[face_column] == "중상"], 1)
        mid_df = df[df[face_column].isin(["중", "중하"])]
        selected_ids += weighted_sample(mid_df, 2)
        selected_ids += weighted_sample(df[df[face_column] == "하"], 1)

    elif my_face_grade == "하":
        selected_ids += weighted_sample(df[df[face_column] == "중"], 1)
        selected_ids += weighted_sample(df[df[face_column] == "중하"], 1)
        selected_ids += weighted_sample(df[df[face_column] == "하"], 2)

    # 혹시 4명이 안 뽑혔을 경우 대비
    selected_ids = selected_ids[:4]
    return selected_ids


# ✅ 후보 추출 함수 (match_members 참조 버전)
def auto_match_members(df, match_data):
    print('auto_match', match_data)
    df["회원 ID"] = df["회원 ID"].astype(str).str.strip()
    match_data["memberId"] = str(match_data["memberId"]).strip()

    target_df = df[df["회원 ID"] == match_data["memberId"]]
    if target_df.empty:
        st.warning("입력한 회원 ID에 해당하는 회원이 없습니다.")
        return pd.DataFrame()

    target = target_df.iloc[0]
    filtered = df.copy()

    numeric_fields = ["상태 FLAG", "본인(키)", "본인(나이)"]
    for field in numeric_fields:
        filtered[field] = pd.to_numeric(filtered[field], errors="coerce")

    filtered = filtered[
        (filtered["성별"] != target["성별"]) &
        (filtered["상태 FLAG"] >= 4) &
        (~filtered["매칭권"].fillna("").str.contains("시크릿"))
        ]
    print('성별,상태,매칭권 필터링 후 : ', filtered)

    # 채널 필터
    if match_data["channel"] and "전체" not in match_data["channel"]:
        valid_channels = []
        channel_map = {"프립(F)": "F", "네이버(N)": "N", "프사오(O)": "O", "인스타(A)": "A", "기타(B)": "B", "기타2(C)": "C"}
        for ch in match_data["channel"]:
            if ch in channel_map:
                valid_channels.append(channel_map[ch])
        filtered = filtered[filtered["주문번호"].astype(str).str[0].isin(valid_channels)]
    print('채널 필터링 후 : ', filtered)

    if match_data.get("faces"):
        filtered = filtered[filtered["등급(외모)"].isin(match_data["faces"])]
        print("외모 필터링 후 : ", filtered)

    if match_data.get("abilitys"):
        filtered = filtered[filtered["등급(능력)"].isin(match_data["abilitys"])]
        print("능력 필터링 후 : ", filtered)

    if match_data.get("faceShape") and match_data["faceShape"] != ["전체"]:
        filtered = filtered[filtered["본인(외모)"].isin(match_data["faceShape"])]
        print("얼굴상 필터링 후 : ", filtered)

    condition_fields = [
        "이상형(키)", "이상형(나이)", "이상형(사는 곳)", "이상형(학력)", "이상형(흡연)",
        "이상형(종교)", "이상형(회사 규모)", "이상형(근무 형태)", "이상형(음주)", "이상형(문신)"
    ]
    profile_fields = [
        "본인(키)", "본인(나이)", "본인(거주지-분류)", "본인(학력)", "본인(흡연)",
        "본인(종교)", "본인(회사 규모)", "본인(근무 형태)", "본인(음주)", "본인(문신)"
    ]

    conds = match_data.get("conditions", [False] * 10)
    for i, use in enumerate(conds):
        if not use:
            continue

        ideal_value = str(target.get(condition_fields[i], "")).strip()
        if not ideal_value:
            continue

        if i in [0, 1]:
            try:
                min_val, max_val = sorted(map(int, ideal_value.replace(" ", "").split("~")))
                filtered[profile_fields[i]] = pd.to_numeric(filtered[profile_fields[i]], errors="coerce")
                filtered = filtered[filtered[profile_fields[i]].between(min_val, max_val)]
                if i == 0:
                    print("키 필터", min_val, max_val)
                    print(filtered)
                else:
                    print("나이 필터", min_val, max_val)
                    print(filtered)
            except:
                pass
        else:
            ideals = set(map(str.strip, ideal_value.split(",")))
            filtered[profile_fields[i]] = filtered[profile_fields[i]].astype(str).str.strip()
            filtered = filtered[filtered[profile_fields[i]].isin(ideals)]

    sent_ids = str(target.get("받은 프로필 목록", "")).split(",") if pd.notna(target.get("받은 프로필 목록")) else []
    sent_ids_set = set(map(str.strip, sent_ids))
    filtered = filtered[~filtered["회원 ID"].astype(str).isin(sent_ids_set)]

    return filtered


def run_multi_matching():
    try:
        request_df, request_ws = load_sheet_with_ws(sheet_name)
        member_df = load_sheet("회원")
        member_df["회원 ID"] = member_df["회원 ID"].astype(str).str.strip()

        row_indices = list(range(3, 32, 4))  # B3, B7, ..., B31

        for base_row in row_indices:
            print(f"🔄 처리 중: Row {base_row}")

            try:
                member_id = str(request_ws.acell(f"B{base_row}").value).strip()
                channel = request_ws.acell(f"C{base_row}").value
                face_grade_raw = request_ws.acell(f"F{base_row}").value or ""
                default_cond = request_ws.acell(f"G{base_row}").value or ""
                override_cond = request_ws.acell(f"H{base_row}").value or ""
                print('id', member_id, channel, default_cond, override_cond)

                default_cond_list = [c.strip() for c in default_cond.split(",") if c.strip()]

                # 나이, 거주지 조건이 없으면 자동 추가
                if "나이" not in default_cond_list:
                    default_cond_list.append("나이")
                if "거주지" not in default_cond_list:
                    default_cond_list.append("거주지")

                # 다시 문자열로 결합
                default_cond = ", ".join(default_cond_list)

                if not member_id:
                    print(f"⚠️ B{base_row} 셀에 회원 ID가 없습니다. 건너뜀")
                    continue

                faces = [s.strip() for s in face_grade_raw.split(",") if s.strip()]

                # 조건 파싱
                condition_str = override_cond if override_cond.strip() else default_cond
                condition_list = [c.strip() for c in condition_str.split(",") if c.strip()]

                # ✅ 조건명 매핑
                condition_name_map = {
                    "키": "키", "나이": "나이", "거주지": "거주지", "학력": "학력",
                    "흡연 여부": "흡연", "흡연": "흡연", "종교 여부": "종교", "종교": "종교",
                    "직장 규모": "회사 규모", "직장": "회사 규모", "근무 형태": "근무 형태", "근무": "근무 형태",
                    "음주 여부": "음주", "음주": "음주", "문신 여부": "문신", "문신": "문신"
                }
                normalized = [condition_name_map.get(c, "") for c in condition_list if
                              condition_name_map.get(c)]
                condition_names = ["키", "나이", "거주지", "학력", "흡연", "종교", "회사 규모", "근무 형태", "음주", "문신"]
                condition_flags = [name in normalized for name in condition_names]

                print(f"🧩 조건: {condition_list}")
                print(f"🧩 정규화 조건: {normalized}")
                print(f"🧩 조건 Flags: {condition_flags}")

                # 후보 추출
                candidates_df = get_profile_candidates(member_id, channel, faces, condition_flags, member_df)
                print(f"🔍 후보 수: {len(candidates_df)}명")

                # 전체 후보 ID 리스트 저장 (K열 = col 11)
                # 등급별로 ID 그룹화
                grouped = candidates_df.groupby("등급(외모)")["회원 ID"].apply(
                    lambda ids: ",".join(ids.astype(str))).to_dict()

                # 출력할 등급 순서 정의
                face_order = ["상", "중상", "중", "중하", "하"]
                formatted_str = ""
                for grade in face_order:
                    if grade in grouped:
                        formatted_str += f"[{grade}]\n{grouped[grade]}\n\n"

                # K열 업데이트
                request_ws.update_cell(base_row, 11, formatted_str.strip())
                print(f"✅ 후보 ID 목록 저장 완료: {formatted_str}")

                # 최종 4명 추출 후 L+1 ~ L+4에 저장
                if not faces:  # 외모조건 미선택 시
                    my_face_grade = member_df[member_df["회원 ID"] == member_id]["등급(외모)"].values[0]
                    top4 = get_custom_face_top4(candidates_df, my_face_grade)
                else:
                    top4 = get_weighted_top4_ids(candidates_df)
                print(f"⭐ 최종 추출된 4명: {top4}")

                for i, pid in enumerate(top4):
                    request_ws.update_cell(base_row + i, 12, pid)

            except Exception as inner_e:
                print(f"❌ Row {base_row} 처리 중 오류: {inner_e}")
                write_log(match_data["memberId"], f"❌ Row {base_row} 처리 중 오류: {inner_e}")

        print("🎉 모든 8명 추출 완료!")

    except Exception as e:
        print(f"❌ 전체 처리 실패: {e}")


def get_phone_number_by_member_id(member_id: str) -> str:
    member_df = load_sheet("회원")
    member_df["회원 ID"] = member_df["회원 ID"].astype(str).str.strip()
    row = member_df[member_df["회원 ID"] == str(member_id).strip()]
    if not row.empty:
        return row.iloc[0].get("휴대폰번호", "010-0000-0000")
    return "010-0000-0000"

AUTO_SAVE_INTERVAL = 3  # 초 단위

def get_profile_memo(member_id):
    df, _ = load_sheet_with_ws("프로필")
    df["회원 ID"] = df["회원 ID"].astype(str).str.strip()
    row = df[df["회원 ID"] == str(member_id).strip()]
    if not row.empty:
        return row.iloc[0].get("메모", "")
    return ""

def save_profile_memo(member_id, new_memo):
    _, ws = load_sheet_with_ws("프로필")
    all_values = ws.get_all_values()
    headers = all_values[1]
    data = all_values[2:]

    if "회원 ID" not in headers or "메모" not in headers:
        return False

    id_idx = headers.index("회원 ID")
    memo_idx = headers.index("메모")

    for i, row in enumerate(data):
        if row[id_idx].strip() == member_id.strip():
            ws.update_cell(i + 3, memo_idx + 1, new_memo)
            return True
    return False


def process_and_upload_watermarked_pdf(member_id, source_url, save_name, target_folder_id):
    import tempfile
    import os

    write_log(member_id, f"make watermark {source_url}, {save_name}, {target_folder_id}")
    try:
        # 🔍 회원 ID로 휴대폰 번호 조회
        phone_number = get_phone_number_by_member_id(member_id)

        # 1. 임시 파일 생성
        input_pdf = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name
        watermark_pdf = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name
        output_pdf = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name


        # 2. 원본 PDF 다운로드
        source_id = extract_drive_file_id(source_url)
        download_pdf_from_drive(source_id, input_pdf)
        write_log(member_id, "Download")

        # 3. 워터마크 PDF 생성 (📱 휴대폰 번호 사용)
        create_watermark(phone_number, watermark_pdf)
        write_log(member_id, "Create")

        # 4. 워터마크 적용된 PDF 생성
        add_watermark_to_pdf(input_pdf, output_pdf, watermark_pdf)
        write_log(member_id,"워터마크 pdf 생성 성공")

        # 5. Google Drive 업로드
        uploaded_id = upload_file_to_drive(output_pdf, save_name, target_folder_id)
        final_link = f"https://drive.google.com/file/d/{uploaded_id}/view?usp=sharing"

        # 6. 임시 파일 정리
        for f in [input_pdf, watermark_pdf, output_pdf]:
            if os.path.exists(f):
                os.remove(f)

        return final_link

    except Exception as e:
        write_log(member_id, f"❌ 워터마크 생성 실패: {e}")
        # 실패 시 임시 파일 삭제
        for f in [input_pdf, watermark_pdf, output_pdf]:
            if f and os.path.exists(f):
                os.remove(f)
        return None


# URL 쿼리를 통해 mulit_bulk_matching 트리거
if trigger == "multi_matching":
    # ✅ 요청 출처 검증을 위한 토큰 검사
    if token != st.secrets.get("apps_script_token"):  # ✅ secrets.toml에 미리 저장된 토큰
        st.error("⛔ 요청 권한 없음")
        write_log("", "❌ 외부 트리거 거부됨: 유효하지 않은 토큰")
        st.stop()

    with st.spinner("외부 트리거에 의해 multi matching 실행 중..."):
        run_multi_matching()
        write_log("", "✅ 외부 트리거: 매칭 완료됨")
        st.stop()

if trigger == "watermark":
    # ✅ 요청 출처 검증을 위한 토큰 검사
    if token != st.secrets.get("apps_script_token"):  # ✅ secrets.toml에 미리 저장된 토큰
        st.error("⛔ 요청 권한 없음")
        write_log("", "❌ 외부 트리거 거부됨: 유효하지 않은 토큰")
        st.stop()
    with st.spinner("📄 워터마크 삽입 중..."):
        try:
            df, ws = load_sheet_with_ws(sheet_name)

            for base_row in range(3, 32, 4):  # B3, B7, ..., B31
                member_id = str(ws.acell(f"B{base_row}").value).strip()
                if not member_id:
                    continue

                # 🔁 J열~S열 데이터 한 번에 읽기 (J~S: 10~19열)
                cell_range = f"L{base_row}:U{base_row + 3}"
                batch_values = ws.get_values(cell_range) # .strip()?

                updates = []  # batch_update용

                for i in range(4):
                    try:
                        row = batch_values[i] if i < len(batch_values) else []
                        pid = row[0] if len(row) > 0 else ""
                        source_link = row[8] if len(row) > 8 else ""

                        if not pid or not source_link:
                            continue

                        source_id = extract_drive_file_id(source_link)
                        new_name = f"{member_id}_프로필카드_{pid}.pdf"
                        folder_id = "104l4k5PPO25thz919Gi4241_IQ_MSsfe"

                        new_link = process_and_upload_watermarked_pdf(member_id, source_link, new_name, folder_id)
                        if new_link:
                            updates.append([new_link])
                            write_log(member_id, f"✅ 워터마크 완료 ({pid}) → 링크 준비 완료")
                        else:
                            updates.append([""])
                            write_log(member_id, f"❌ 워터마크 실패 ({pid})")
                    except Exception as e:
                        updates.append([""])
                        write_log(member_id, f"❌ 오류 ({pid if 'pid' in locals() else '?'}): {e}")

                # ✅ 한번에 U열에 결과 저장
                if updates:
                    ws.update(f"U{base_row}:U{base_row + len(updates) - 1}", updates)

            write_log("", "✅ 외부 트리거: 워터마크 완료됨")
            st.success("✅ 모든 워터마크 처리 완료")
            st.stop()
        except Exception as e:
            st.error(f"❌ 전체 워터마크 처리 실패: {e}")
            write_log("", f"❌ 워터마크 처리 중 오류: {e}")
            st.stop()




# ---------------------------
# Streamlit UI
# ---------------------------

code = params.get("code", [None])
if not st.session_state["logged_in"] and code == [None]:
    st.title("🔐 Google 로그인")
    query = urlencode({
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
    })
    login_url = f"{AUTHORIZATION_ENDPOINT}?{query}"
    st.markdown(f"[🔑 Google 계정으로 로그인]({login_url})")
    st.stop()

elif code and not st.session_state["logged_in"]:
    # st.write(st.session_state["logged_in"])

    # ✅ 코드로 토큰 요청
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": st.secrets["google"]["client_secret"],
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    # 응답 그대로 저장
    token_res = requests.post(TOKEN_ENDPOINT, data=data)
    # st.write(data)
    # st.write(token_res)
    try:
        # ✅ JSON 응답 파싱
        token_data = token_res.json()
        # st.write("🔄 token_res 응답:")
        id_token = token_data.get("id_token")
        access_token = token_data.get("access_token")

        if id_token and access_token:
            st.query_params.clear()  # 로그인 성공 후 인증코드 제거
            req = google.auth.transport.requests.Request()
            id_info = google.oauth2.id_token.verify_oauth2_token(id_token, req, CLIENT_ID)
            user_email = id_info.get("email")
            user_name = id_info.get("name", user_email)
            st.session_state["user_id"] = user_email

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # ✅ 계정정보 시트 연결 및 불러오기
            df_accounts, ws_accounts = connect_sheet("가입허용")
            df_memo, ws_memo = connect_sheet("메모")
            df_log, ws_log = connect_sheet("로그인기록")

            if "가입허용" not in df_accounts.columns:
                st.error("❌ [가입허용] 시트에 '가입허용' 컬럼이 없습니다. 관리자에게 문의해주세요.")
                st.stop()
            df_accounts.columns = [col.strip() for col in df_accounts.columns]

            if "이메일" not in df_accounts.columns:
                ws_accounts.update("A1:D1", [["이메일", "이름", "가입허용", "마지막 로그인 시간"]])
                df_accounts = pd.DataFrame(columns=["이메일", "이름", "가입허용", "마지막 로그인 시간"])

            if user_email not in df_accounts["이메일"].values:
                ws_accounts.append_row([user_email, user_name, "", now])
                st.warning("📬 관리자 승인이 필요합니다. 가입 요청이 기록되었습니다.")
                st.stop()
            else:
                row_index = df_accounts.index[df_accounts["이메일"] == user_email][0] + 2
                ws_accounts.update(f"D{row_index}", [[now]])

                user_row = df_accounts.loc[df_accounts["이메일"] == user_email].iloc[0]
                if str(user_row.get("가입허용", "")).strip().upper() == "O":
                    st.session_state["logged_in"] = True

                    # ✅ 메모 시트 등록 여부 확인
                    if user_email not in df_memo["이메일"].values:
                        ws_memo.append_row([user_email, "", now])

                    # ✅ 로그인기록 시트 추가
                    try:
                        next_seq = len(df_log) + 1
                        ws_log.append_row([next_seq, user_email, now])
                    except Exception as e:
                        st.error(f"로그인 기록 저장 실패: {e}")
                        write_log(user_email, f"로그인 기록 저장 실패: {e}")

                    st.rerun()
                    ############################# 시작 #########################################

                    ############################## 끝 ################################################
                else:
                    st.warning("⛔ 아직 관리자 승인 대기 중입니다. 가입 요청은 이미 등록되었습니다.")
                    st.stop()
        else:
            st.error("❌ 로그인 인증코드가 유효하지 않거나 만료되었습니다. 다시 로그인해주세요.")
            st.query_params.clear()  # ✅ 인증 실패 시 code 파라미터 삭제
            st.stop()
    except Exception as e:
        st.error(f"❌ 응답 파싱 실패: {e}")
        st.stop()
else:
    st.sidebar.success(f"✅ {st.session_state['user_id']} 님 로그인됨")
    if st.sidebar.button("🔓 로그아웃"):
        st.session_state.clear()
        st.query_params.clear()
        st.rerun()
    if "last_rerun_time" not in st.session_state:
        st.session_state["last_rerun_time"] = time.time()

    now = time.time()
    if now - st.session_state["last_rerun_time"] > 300:  # 300초 = 5분
        st.session_state["last_rerun_time"] = now
        st.rerun()

    with tab1:
        st.title("\U0001F4CB 회원 프로필 매칭 시스템")

        try:
            member_df = load_sheet("회원")
            profile_df = load_sheet("프로필")
        except Exception as e:
            st.error("시트를 불러오는 데 실패했습니다: " + str(e))
            write_log("", "시트 로딩 실패")
            st.stop()

        with st.sidebar:
            st.subheader("\U0001F50D 필터 설정")

            # 회원 ID 입력 + 회원 정보 조회 버튼 한 줄로
            id_col1, id_col2 = st.columns(2)
            memberId = id_col1.text_input("회원 ID 입력", "1318", label_visibility="collapsed")
            info_button = id_col2.button("\U0001F464 회원 정보 조회", use_container_width=True)

            # 채널 선택 + 얼굴형 선택 나란히
            ch_col1, ch_col2 = st.columns(2)
            channel_options = ["전체", "프립(F)", "네이버(N)", "프사오(O)", "인스타(A)", "기타(B)", "기타2(C)"]
            channel = ch_col1.multiselect("채널 선택", channel_options, default=["전체"])

            all_faceshapes = ["전체"] + sorted(member_df["본인(외모)"].dropna().unique().tolist())
            face_shape = ch_col2.multiselect("선호 얼굴형", all_faceshapes, default=["전체"])

            # 외모 등급 + 능력 등급 나란히
            grade_col1, grade_col2 = st.columns(2)
            face_order = ["상", "중상", "중", "중하", "하"]
            face_values = sorted(set(member_df["등급(외모)"].dropna()) - set(face_order))
            faces = grade_col1.multiselect("외모 등급", face_order + face_values)

            ability_order = ["상", "중", "하"]
            ability_values = sorted(set(member_df["등급(능력)"].dropna()) - set(ability_order))
            abilitys = grade_col2.multiselect("능력 등급", ability_order + ability_values)

            after_date = st.date_input("설문 이후 날짜 필터", value=None)

            st.markdown("**추가 필터:**")

            # ✅ 선택 조건 자동 반영
            selected_conditions = st.session_state.get("selected_conditions", [])

            cols = st.columns(4)
            conds = [
                cols[0].checkbox("키", value="키" in selected_conditions),
                cols[1].checkbox("나이", value="나이" in selected_conditions),
                cols[2].checkbox("거주지", value="거주지" in selected_conditions),
                cols[3].checkbox("학력", value="학력" in selected_conditions),
                cols[0].checkbox("흡연", value="흡연" in selected_conditions),
                cols[1].checkbox("종교", value="종교" in selected_conditions),
                cols[2].checkbox("회사 규모", value="회사 규모" in selected_conditions or "회사규모" in selected_conditions),
                cols[3].checkbox("근무 형태", value="근무 형태" in selected_conditions or "근무형태" in selected_conditions),
                cols[0].checkbox("음주", value="음주" in selected_conditions),
                cols[1].checkbox("문신", value="문신" in selected_conditions)
            ]

            match_button = st.button("\U0001F50E 프로필 추출")

            st.markdown("---")

            st.title(f"👤 {st.session_state['user_id']}님 접속 중")
            col1, col2 = st.columns([1, 1])
            with col1:
                if st.button("🚪 로그아웃"):
                    st.session_state.clear()
                    st.rerun()

            with col2:
                if st.button("🔄 수동 새로고침"):
                    st.cache_data.clear()
                    st.cache_resource.clear()  # ✅ 추가!
                    st.session_state["last_rerun_time"] = time.time()
                    st.rerun()

        if "member_info_triggered" not in st.session_state:
            st.session_state["member_info_triggered"] = False
        if "selected_conditions" not in st.session_state:
            st.session_state["selected_conditions"] = []
        if "match_triggered" not in st.session_state:
            st.session_state["match_triggered"] = False

        if info_button:
            st.session_state["member_info_triggered"] = True
            st.session_state["match_triggered"] = False

        if match_button:
            st.session_state["match_triggered"] = True

        # 회원 정보 조회 출력 컨테이너 (항상 위)
        info_container = st.container()
        # 프로필 추출 결과 출력 컨테이너 (항상 아래)
        match_container = st.container()

        with info_container:
            if st.session_state["member_info_triggered"]:
                target_member = member_df[member_df["회원 ID"] == memberId]
                if target_member.empty:
                    st.warning("입력한 회원 ID에 해당하는 회원이 없습니다.")
                else:
                    m = target_member.iloc[0]
                    member_id_str = m.get("회원 ID", "")
                    st.markdown(f"### 🔍 {member_id_str} 회원 기본 정보")

                    info_rows = [
                        ("프로필 ID", m.get("프로필 ID", "")),
                        ("카톡 ID", f"{m.get('주문번호', '')}_{m.get('매칭권', '')}"),
                        ("주문번호", m.get("주문번호", "")),
                        ("매칭권", m.get("매칭권", "")),
                        ("상태", m.get("상태", "")),
                        ("담당자", m.get("담당자", "")),
                        ("등급(외모 - 능력)", f"{m.get('등급(외모)', '')} - {m.get('등급(능력)', '')}"),
                        ("받은 프로필 수", m.get("받은 프로필 수", "")),
                        ("선택 조건", m.get("선택 조건", "")),
                        ("기존 회원", m.get("기존 회원", "")),
                        ("비고", m.get("비고", "")),
                        ("본인 얼굴상", m.get("본인(외모)", "")),
                    ]

                    for i in range(0, len(info_rows), 3):
                        cols = st.columns(3)
                        for j in range(3):
                            if i + j < len(info_rows):
                                label, value = info_rows[i + j]
                                cols[j].markdown(f"**{label}**: {value}")

                    # 받은 프로필 목록
                    if m.get("받은 프로필 목록", ""):
                        with st.expander("📨 받은 프로필 목록 보기"):
                            st.markdown(m.get("받은 프로필 목록", ""))

                    # 이상형 전달
                    profile_text = m.get("이상형", "")
                    with st.expander("📋 이상형 내용 보기"):
                        st.code(profile_text, language="text")

                    # 프로필 전달
                    profile_text = m.get("프로필(전달)", "")
                    with st.expander("📋 프로필(전달) 내용 보기"):
                        st.code(profile_text, language="text")
                    with st.expander("📸 사진 보기"):
                        # ✅ 프로필 사진 표시 및 변경 최적화
                        # 이미지 캐시 딕셔너리 초기화
                        if "image_cache_dict" not in st.session_state:
                            st.session_state["image_cache_dict"] = {}
                        image_cache = st.session_state["image_cache_dict"]

                        photo_urls = str(m.get("본인 사진", "")).split(',')
                        photo_cols = st.columns(min(5, len(photo_urls)))

                        for i, url in enumerate(photo_urls[:5]):
                            url = url.strip()

                            with photo_cols[i]:
                                if url.lower() in ["n/a", "본인사진"] or not url:
                                    continue

                                file_id = extract_drive_file_id(url)
                                if not file_id:
                                    st.warning("유효하지 않은 이미지 링크입니다.")
                                    continue

                                try:
                                    if file_id in image_cache:
                                        img_b64 = image_cache[file_id]
                                    else:
                                        image = get_drive_image(file_id)
                                        img_b64 = image_to_base64(image)
                                        image_cache[file_id] = img_b64

                                    st.markdown(
                                        f'<a href="{url}" target="_blank">'
                                        f'<img src="data:image/png;base64,{img_b64}" style="width:130px;border-radius:10px;"/>'
                                        f'</a>',
                                        unsafe_allow_html=True
                                    )
                                except Exception:
                                    st.warning("이미지 로드 실패")
                                    write_log("", "이미지 로드 실패")

                                uploaded_file = st.file_uploader(f"새 이미지 업로드 {i + 1}", type=["jpg", "jpeg", "png"],
                                                                 key=f"upload_{i}")
                                if uploaded_file:
                                    file_name = f"{member_id_str}_본인사진_{i + 1}.jpg"
                                    temp_file_path = f"temp_{file_name}"
                                    with open(temp_file_path, "wb") as f:
                                        f.write(uploaded_file.read())

                                    original_file_id = None
                                    if i < len(photo_urls):
                                        original_url = photo_urls[i].strip()
                                        original_file_id = extract_drive_file_id(original_url)

                                    uploaded_id = upload_image_to_drive(temp_file_path, file_name,
                                                                        original_file_id=original_file_id)
                                    new_url = f"https://drive.google.com/file/d/{uploaded_id}/view?usp=sharing"
                                    os.remove(temp_file_path)

                                    # ✅ 기존 캐시 삭제
                                    if "image_cache_dict" in st.session_state:
                                        if original_file_id in st.session_state["image_cache_dict"]:
                                            st.session_state["image_cache_dict"].pop(original_file_id, None)

                                    # 프로필 사진 시트 업데이트
                                    if update_profile_photo_in_sheet(member_id_str, i, new_url):
                                        st.success(f"✅ 변경 완료, 수동 새로고침 필요")
                                        photo_urls = get_latest_profile_photo(member_id_str)  # ✅ 최신 J열만 다시 읽기
                                    else:
                                        st.error("❌ 시트 업데이트 실패")

                    st.markdown("---")

        with match_container:
            if st.session_state["match_triggered"]:
                with st.spinner("매칭 중..."):
                    match_data = {
                        "memberId": memberId,
                        "channel": channel,
                        "faceShape": face_shape,
                        "faces": faces,
                        "abilitys": abilitys,
                        "afterDate": after_date if after_date else None,
                        "conditions": conds
                    }

                    result_df = match_members(member_df, match_data)
                    st.subheader(f"📝 {memberId} 조건에 매칭된 총 회원 수: {len(result_df)}명")

                    score_values = result_df["보내진 횟수"].fillna(0)
                    score_values = pd.to_numeric(score_values, errors="coerce").fillna(0)
                    weights = 1 / (score_values + 1)

                    if weights.sum() > 0 and len(result_df) > 0:
                        top_ids = result_df.sample(n=min(4, len(result_df)), weights=weights, random_state=42)[
                            "회원 ID"].tolist()
                    else:
                        top_ids = result_df.head(4)["회원 ID"].tolist()

                    with st.expander("\U0001F4CB 조건에 매칭된 회원 리스트 보기 (클릭)"):
                        st.dataframe(result_df[["회원 ID", "이름", "보내진 횟수"]].reset_index(drop=True), height=200)

                    if "top_ids" not in st.session_state:
                        st.session_state["top_ids"] = []
                    if "top_rows" not in st.session_state:
                        st.session_state["top_rows"] = pd.DataFrame()
                    if "matched_profiles" not in st.session_state:
                        st.session_state["matched_profiles"] = pd.DataFrame()

                    if st.session_state["match_triggered"]:
                        st.session_state["top_ids"] = top_ids
                        st.session_state["top_rows"] = profile_df[profile_df["회원 ID"].isin(st.session_state["top_ids"])]
                        st.session_state["matched_profiles"] = profile_df[
                            profile_df["회원 ID"].isin(st.session_state["top_ids"])]

                    st.markdown("---")
                    st.subheader("🛠️ 추출된 프로필 관리")

                    # 1. 랜덤 다시 보기
                    if st.button("🔀 추출된 프로필 랜덤 다시 뽑기"):
                        available_df = result_df[~result_df["회원 ID"].isin(st.session_state["top_ids"])]
                        if available_df.empty:
                            st.error("❌ 추가로 뽑을 수 있는 회원이 없습니다.")
                        else:
                            score_values = available_df["보내진 횟수"].fillna(0).astype(float)
                            weights = 1 / (score_values + 1)
                            new_top_ids = \
                            available_df.sample(n=min(4, len(available_df)), weights=weights, random_state=None)[
                                "회원 ID"].tolist()
                            st.session_state["top_ids"] = new_top_ids

                            # ✅ 추가: top_rows, matched_profiles 갱신!
                            st.session_state["top_rows"] = member_df[
                                member_df["회원 ID"].isin(st.session_state["top_ids"])]
                            st.session_state["matched_profiles"] = profile_df[
                                profile_df["회원 ID"].isin(st.session_state["top_ids"])]

                            st.success("✅ 추출 완료")

                    # 2. 객체 ID 교체
                    with st.expander("✏️ 직접 4개 회원 ID 입력해서 교체하기"):
                        input_cols = st.columns(4)
                        for i in range(4):
                            input_cols[i].text_input(f"{i + 1}번 교체할 회원 ID", key=f"replace_input_{i}")

                        # 교체 버튼 클릭 시
                        if st.button("✏️ 입력된 ID로 교체하기"):
                            updated = False
                            replace_inputs = [st.session_state.get(f"replace_input_{i}", "").strip() for i in range(4)]

                            for idx, new_id in enumerate(replace_inputs):
                                if new_id:
                                    if new_id in member_df["회원 ID"].astype(str).tolist():
                                        if new_id not in st.session_state["top_ids"]:
                                            st.session_state["top_ids"][idx] = new_id
                                            updated = True
                                        else:
                                            st.error(f"❌ {idx + 1}번 칸: 이미 선택된 회원입니다.")
                                    else:
                                        st.error(f"❌ {idx + 1}번 칸: 입력한 회원 ID {new_id}는 전체 회원 목록에 없습니다.")

                            if updated:
                                st.success("✅ 입력된 ID로 프로필 교체를 완료했습니다.")
                                # ✅ top_rows, matched_profiles 갱신!!
                                st.session_state["top_rows"] = member_df[
                                    member_df["회원 ID"].isin(st.session_state["top_ids"])]
                                st.session_state["matched_profiles"] = profile_df[
                                    profile_df["회원 ID"].isin(st.session_state["top_ids"])]

                    # 프로필 표시 부분
                    top_rows = st.session_state.get("top_rows", pd.DataFrame())
                    matched_profiles = st.session_state.get("matched_profiles", pd.DataFrame())

                    st.markdown("---")
                    st.subheader(f"📄 {memberId} 조건에 매칭된 상위 4명 프로필")
                    columns = st.columns(4)

                    for idx, member_id in enumerate(st.session_state["top_ids"]):
                        match_row = matched_profiles[matched_profiles["회원 ID"] == member_id]
                        score_row = top_rows[top_rows["회원 ID"] == member_id]
                        member_row = member_df[member_df["회원 ID"] == member_id]
                        if match_row.empty or score_row.empty or member_row.empty:
                            continue
                        row = match_row.iloc[0]
                        score_info = score_row.iloc[0]

                        with columns[idx]:
                            주문번호 = member_row.iloc[0].get("주문번호", "")
                            이름 = row.get("이름", "")
                            보내진횟수 = score_info.get("보내진 횟수", "")

                            st.markdown(f"**주문번호 및 이름:** {주문번호} / {이름}")
                            st.markdown(f"**회원 ID:** {row.get('회원 ID', '')}")
                            st.markdown(f"**프로필 ID:** {row.get('프로필 ID', '')}")
                            st.markdown(f"**보내진 횟수:** {보내진횟수}")
                            st.markdown(f"**얼굴상:** {row.get('본인(외모)', '')}")

                            profile_text = row.get("프로필(전달)", "")
                            with st.expander("프로필(전달) 보기"):
                                st.code(profile_text, language='text')

                            with st.expander("📸 사진 보기"):
                                photo_urls = str(row.get("본인 사진", "")).split(',')
                                for i, url in enumerate(photo_urls):
                                    url = url.strip()
                                    if "drive.google.com" in url and "id=" in url:
                                        file_id = url.split("id=")[-1].split("&")[0]
                                        try:
                                            image = get_drive_image(file_id)
                                            img_b64 = image_to_base64(image)
                                            st.markdown(
                                                f'<a href="{url}" target="_blank"><img src="data:image/png;base64,{img_b64}" style="width:150px;border-radius:10px;"/></a>',
                                                unsafe_allow_html=True
                                            )
                                        except Exception as e:
                                            st.warning(f"이미지 로드 실패: {e}")
                                            write_log("", f"이미지 로드 실패: {e}")
                                    else:
                                        st.warning("유효하지 않은 이미지 링크입니다.")

    with tab2:

        # 받은 프로필 수를 숫자로 변환
        member_df["받은 프로필 수"] = pd.to_numeric(member_df["받은 프로필 수"], errors="coerce").fillna(0)

        # 🔥 상태가 '검증완료'인 회원만 필터링
        verified_members = member_df[member_df["상태"] == "검증완료"]

        # 받은 프로필 수 그룹 나누기
        group1 = verified_members[(verified_members["받은 프로필 수"] >= 0) & (verified_members["받은 프로필 수"] <= 3)]
        group2 = verified_members[(verified_members["받은 프로필 수"] >= 4) & (verified_members["받은 프로필 수"] <= 7)]
        group3 = verified_members[(verified_members["받은 프로필 수"] >= 8) & (verified_members["받은 프로필 수"] <= 11)]

        columns_to_show = ["회원 ID", "이름", "등급(외모)", "등급(능력)", "받은 프로필 수"]

        st.markdown(f"### 🥇 받은 프로필 수 0~3개 회원 ({len(group1)}명)")
        st.dataframe(group1[columns_to_show].reset_index(drop=True))

        st.markdown(f"### 🥈 받은 프로필 수 4~7개 회원 ({len(group2)}명)")
        st.dataframe(group2[columns_to_show].reset_index(drop=True))

        st.markdown(f"### 🥉 받은 프로필 수 8~11개 회원 ({len(group3)}명)")
        st.dataframe(group3[columns_to_show].reset_index(drop=True))

    with tab3:
        st.subheader("🖼️ 회원 ID별 4개 프로필 사진 보기")

        sheet_url = "https://docs.google.com/spreadsheets/d/1jnZqqmZB8zWau6CHqxm-L9fxlXDaWxOaJm6uDcE6WN0/edit"
        worksheet_name = '테스트용(하태훈)2의 사본'
        df, _ = load_sheet_with_ws(worksheet_name)

        # 첫 번째 열(회원 ID가 있는 열) 기준으로 B3, B7, ..., B31 위치 인덱싱
        member_indices = [0, 4, 8, 12, 16, 20, 24, 28]
        member_ids = df.iloc[member_indices, 1].dropna().astype(str).tolist()
        selected_member = st.selectbox("🔎 회원 ID 선택", member_ids)

        if selected_member:
            st.markdown(f"📌 선택한 회원 ID: `{selected_member}`")
            selected_idx = df[df.iloc[:, 1] == selected_member].index[0]

            # 매칭된 4개 프로필의 회원 ID (J열: 열 index 9)
            profile_ids = df.iloc[selected_idx:selected_idx + 4, 9].astype(str).tolist()

            # 이미지 캐시 딕셔너리 초기화
            if "image_cache_dict" not in st.session_state:
                st.session_state["image_cache_dict"] = {}
            image_cache = st.session_state["image_cache_dict"]

            # 각 프로필 사진 출력 (M~Q열)
            for i, pid in enumerate(profile_ids):
                st.markdown(f"👤 **프로필 {i + 1} - 회원ID {pid}**")
                img_cols = st.columns(5)

                for j, col in enumerate(img_cols):
                    try:
                        link = df.iloc[selected_idx + i, 12 + j]  # M~Q열 → 열 index 12~16
                        link = link.strip()

                        if link.lower() in ["n/a", "본인사진"] or not link:
                            continue  # 메시지 출력 없이 무시

                        file_id = extract_drive_file_id(link)
                        if not file_id:
                            continue

                        # 이미지 캐시 활용
                        if file_id in image_cache:
                            img_b64 = image_cache[file_id]
                        else:
                            image = get_drive_image2(file_id)
                            img_b64 = image_to_base64(image)
                            image_cache[file_id] = img_b64

                        with col:
                            st.markdown(
                                f'<a href="{link}" target="_blank">'
                                f'<img src="data:image/png;base64,{img_b64}" style="width:300px;border-radius:10px;"/>'
                                f'</a>',
                                unsafe_allow_html=True
                            )

                    except Exception:
                        pass  # 로딩 실패 시 무시

    with tab4:

        # ✅ 메모 저장 함수
        def save_memo_to_sheet(user_id, memo_content):
            df_memo, ws_memo = connect_sheet("메모")
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            user_rows = df_memo[df_memo["이메일"] == user_id]

            if not user_rows.empty:
                row_idx = user_rows.index[0] + 2
                ws_memo.update_cell(row_idx, 2, memo_content)  # 메모 내용 수정
                ws_memo.update_cell(row_idx, 3, now_str)  # 저장 시간도 같이 수정
            else:
                next_row = len(df_memo) + 3
                ws_memo.update_cell(next_row, 1, user_id)
                ws_memo.update_cell(next_row, 2, memo_content)
                ws_memo.update_cell(next_row, 3, now_str)


        # ✅ 메모 불러오기 함수
        def load_memo_from_sheet(user_id):
            df_memo, ws_memo = connect_sheet("메모")
            user_rows = df_memo[df_memo["이메일"] == user_id]
            if not user_rows.empty:
                return user_rows.iloc[0]["메모"]
            else:
                return ""


        st.subheader("📝 작업자 메모장")

        # ✅ 로그인한 사용자 ID
        user_id = st.session_state["user_id"]

        # ✅ 메모 불러오기 (최초 1번만)
        if f"memo_content_{user_id}" not in st.session_state:
            loaded_memo = load_memo_from_sheet(user_id)
            st.session_state[f"memo_content_{user_id}"] = loaded_memo

        # ✅ 메모 입력창
        memo = st.text_area("메모를 자유롭게 작성하세요!",
                            value=st.session_state[f"memo_content_{user_id}"],
                            height=300,
                            key=f"memo_editor_{user_id}")

        # ✅ 저장 버튼
        if st.button("💾 저장하기"):
            save_memo_to_sheet(user_id, memo)
            st.session_state[f"memo_content_{user_id}"] = memo
            st.success("✅ 메모가 저장되었습니다.")

    with tab5:
        st.header("📝 회원 메모 작성")

        member_id_input = st.text_input("회원 ID를 입력하세요", "")

        if member_id_input:
            session_key = f"memo_{member_id_input}"

            # ✅ 세션 상태 초기화
            if session_key not in st.session_state:
                st.session_state[session_key] = get_profile_memo(member_id_input)
                st.session_state[f"{session_key}_last_saved"] = time.time()
                st.session_state[f"{session_key}_last_input"] = time.time()

            # ✅ 메모 입력창
            new_memo = st.text_area(
                "회원 메모",
                st.session_state[session_key],
                height=200,
                key=f"textarea_{member_id_input}"
            )

            # ✅ 입력 변경 감지
            if new_memo != st.session_state[session_key]:
                st.session_state[session_key] = new_memo
                st.session_state[f"{session_key}_last_input"] = time.time()

            # ✅ 자동 저장 조건
            now = time.time()
            last_input = st.session_state.get(f"{session_key}_last_input", 0)
            last_saved = st.session_state.get(f"{session_key}_last_saved", 0)
            if now - last_input >= 10 and last_input > last_saved:
                if save_profile_memo(member_id_input, new_memo):
                    st.toast("✅ 자동 저장 완료", icon="💾")
                    write_log(member_id_input, "프로필 메모 자동 저장됨")
                    st.session_state[f"{session_key}_last_saved"] = now

            # ✅ 수동 저장 버튼
            if st.button("💾 메모 저장"):
                if save_profile_memo(member_id_input, new_memo):
                    st.success("✅ 저장 완료")
                    write_log(member_id_input, "프로필 메모 수동 저장됨")
                    st.session_state[f"{session_key}_last_saved"] = time.time()

    with tab6:
        st.subheader("📇 회원 ID로 프로필카드 생성")

        member_id_input = st.text_input("회원 ID 입력", key="profilecard_input")

        if st.button("📄 프로필카드 생성하기", key="profilecard_generate"):
            if not member_id_input.strip():
                st.warning("회원 ID를 입력해주세요.")
            else:
                with st.spinner("프로필카드를 생성 중입니다..."):
                    try:
                        uploaded_id = generate_profile_card_from_sheet(member_id_input.strip())
                        file_url = f"https://drive.google.com/file/d/{uploaded_id}/view?usp=sharing"
                        st.success("✅ 프로필카드 생성 완료!")
                        st.markdown(f"[📄 생성된 프로필카드 보기]({file_url})", unsafe_allow_html=True)
                    except Exception as e:
                        st.error(f"❌ 오류 발생: {e}")
