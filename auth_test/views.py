from google.oauth2 import id_token
from google.auth.transport import requests
from django.http import JsonResponse
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials


def google_auth(request):
    token = request.GET.get('token')
    try:
        user_info = id_token.verify_oauth2_token(token, requests.Request())
        return JsonResponse({'user_info': user_info})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


def upload_file(request):
    credentials = Credentials.from_authorized_user_info(request.user)
    drive_service = build('drive', 'v3', credentials=credentials)

    file_metadata = {'name': 'test_file.txt'}
    media = MediaFileUpload('test_file.txt', mimetype='text/plain')

    file = drive_service.files().create(
        body=file_metadata, media_body=media, fields='id'
    ).execute()

    return JsonResponse({'file_id': file.get('id')})