from utils import allowed_file, get_file_mimetype, _sanitize_input, _load_data, _save_data, _log_event, _generate_display_id, _deobfuscate_url, _is_private_ip
from config import ALLOWED_MEDIA_EXTENSIONS, MAX_FILE_SIZE_BYTES, MAX_FILE_SIZE_MB, ALLOWED_UPLOAD_MIME_TYPES
from flask import Blueprint, request, jsonify, session
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from config import *
import requests
import socket
import ipaddress
from datetime import datetime
import tempfile
import os
import uuid

bp_upload = Blueprint('bp_upload', __name__)

@bp_upload.route('/upload_image', methods=['POST'])
def upload_image():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part in the request.'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file.'}), 400
    if not allowed_file(file.filename, ALLOWED_MEDIA_EXTENSIONS):
        return jsonify({'success': False, 'message': 'File type not allowed by extension.'}), 400
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > MAX_FILE_SIZE_BYTES:
        return jsonify({'success': False, 'message': f'File size exceeds {MAX_FILE_SIZE_MB}MB limit.'}), 413
    try:
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(filepath)
        actual_mimetype = get_file_mimetype(filepath)
        if actual_mimetype not in ALLOWED_UPLOAD_MIME_TYPES:
            os.remove(filepath)
            _log_event(session['username'], f"Blocked upload due to disallowed MIME type: {actual_mimetype} for file {filename}.")
            return jsonify({'success': False, 'message': 'Uploaded file has an unsupported content type.'}), 400
        title = _sanitize_input(request.form.get('title'), 'text', max_length=255)
        if not title:
            title = os.path.splitext(filename)[0]
        description = _sanitize_input(request.form.get('description', 'no description provided'), 'text', max_length=1000)
        group_name = _sanitize_input(request.form.get('group_name', 'Unsorted'), 'name', max_length=100)
        application_data = _load_data()
        image_id = str(uuid.uuid4())
        image_entry = {
            'id': image_id,
            'filename': unique_filename,
            'url': f'/uploads/{unique_filename}',
            'title': title,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'uploadedBy': session['username'],
            'uploadedByDisplayId': session['displayId'],
            'group': group_name,
            'type': 'original',
            'actual_mimetype': actual_mimetype
        }
        application_data['images'].append(image_entry)
        if not any(coll['name'] == group_name for coll in application_data.get('image_collections', [])):
            application_data.setdefault('image_collections', []).append({'name': group_name})
        _save_data(application_data)
        _log_event(session['username'], f"Uploaded image: {filename} (ID: {image_id}) to group '{group_name}'.")
        return jsonify({'success': True, 'message': 'Image uploaded successfully!', 'imageId': image_id}), 200
    except Exception as e:
        _log_event(session['username'], f"Error uploading image: {str(e)}")
        return jsonify({'success': False, 'message': f'Error uploading image: {str(e)}'}), 500

@bp_upload.route('/upload_image_url', methods=['POST'])
def upload_image_url():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_url = request_payload.get('imageUrl')
    title = _sanitize_input(request_payload.get('title', ''), 'text', max_length=255)
    description = _sanitize_input(request_payload.get('description', 'no description provided'), 'text', max_length=1000)
    group_name = _sanitize_input(request_payload.get('group_name', 'Unsorted'), 'name', max_length=100)
    if not image_url:
        return jsonify({'success': False, 'message': 'Image URL is required.'}), 400
    deobfuscated_image_url = _deobfuscate_url(image_url)
    if deobfuscated_image_url != image_url:
        _log_event(session['username'], f"Deobfuscated URL from '{image_url}' to '{deobfuscated_image_url}'.")
    image_url_to_check = deobfuscated_image_url
    parsed_url = urlparse(image_url_to_check)
    if parsed_url.scheme not in ['http', 'https']:
        _log_event(session['username'], f"Blocked URL upload due to disallowed scheme: {parsed_url.scheme} for URL {image_url_to_check}.")
        return jsonify({'success': False, 'message': 'Only HTTP and HTTPS URLs are allowed.'}), 400
    hostname = parsed_url.hostname
    if hostname:
        if hostname.lower() in ['localhost', '127', '127.0.0.1', '0.0.0.0', '::1']:
            _log_event(session['username'], f"SSRF attempt blocked: Explicit loopback hostname '{hostname}' detected in URL {image_url_to_check}.")
            return jsonify({'success': False, 'message': 'Access to internal resources is denied.'}), 400
        try:
            ip_addresses = socket.gethostbyname_ex(hostname)[2]
            _log_event(session['username'], f"Resolved hostname '{hostname}' to IPs: {ip_addresses}")
            app_host_ip = None
            try:
                app_host_ip = socket.gethostbyname(request.host.split(':')[0])
            except socket.gaierror:
                pass
            for ip_addr in ip_addresses:
                if _is_private_ip(ip_addr) or ipaddress.ip_address(ip_addr) == AWS_METADATA_IP:
                    _log_event(session['username'], f"SSRF attempt blocked: {image_url_to_check} resolved to private/blocked IP {ip_addr}")
                    return jsonify({'success': False, 'message': 'Access to internal resources is denied.'}), 400
                target_port = parsed_url.port
                if target_port is None:
                    target_port = 80 if parsed_url.scheme == 'http' else (443 if parsed_url.scheme == 'https' else None)
                if target_port in OUTBOUND_BLOCKED_PORTS:
                    _log_event(session['username'], f"SSRF attempt blocked: Outbound connection to blocked port {target_port} for URL {image_url_to_check}.")
                    return jsonify({'success': False, 'message': f'Access to port {target_port} is denied for security reasons.'}), 400
                app_port_str = request.host.split(':')[0] if ':' not in request.host else request.host.split(':')[-1]
                if app_host_ip and ip_addr == app_host_ip and str(target_port) == app_port_str:
                    _log_event(session['username'], f"SSRF attempt blocked: Attempt to connect back to self ({image_url_to_check}) via IP {ip_addr} and port {target_port}.")
                    return jsonify({'success': False, 'message': 'Access to internal resources is denied.'}), 400
        except socket.gaierror:
            _log_event(session['username'], f"SSRF warning: Hostname {hostname} could not be resolved for URL {image_url_to_check}.")
            return jsonify({'success': False, 'message': 'Invalid or unresolvable image URL hostname.'}), 400
    else:
        return jsonify({'success': False, 'message': 'Invalid image URL (no hostname).'}), 400
    _log_event(session['username'], f"Attempting to fetch URL: {image_url_to_check}")
    try:
        response = requests.get(image_url_to_check, stream=True, timeout=10)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '').lower()
        if content_type not in ALLOWED_UPLOAD_MIME_TYPES:
            _log_event(session['username'], f"Blocked URL upload due to disallowed content type header: {content_type} for URL {image_url_to_check}.")
            return jsonify({'success': False, 'message': 'Unsupported image content type from URL header.'}), 400
        total_size = 0
        temp_filepath = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
        with open(temp_filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    total_size += len(chunk)
                    if total_size > MAX_FILE_SIZE_BYTES:
                        os.remove(temp_filepath)
                        return jsonify({'success': False, 'message': f'Downloaded file size exceeds {MAX_FILE_SIZE_MB}MB limit.'}), 413
                    f.write(chunk)
        original_filename = os.path.basename(urlparse(image_url_to_check).path)
        if not original_filename:
            original_filename = "downloaded_image"
        if not allowed_file(original_filename, ALLOWED_MEDIA_EXTENSIONS):
            os.remove(temp_filepath)
            return jsonify({'success': False, 'message': 'Determined file type from URL is not allowed by extension or contains forbidden double extension.'}), 400
        actual_mimetype_after_download = get_file_mimetype(temp_filepath)
        if actual_mimetype_after_download not in ALLOWED_UPLOAD_MIME_TYPES:
            os.remove(temp_filepath)
            _log_event(session['username'], f"Blocked URL upload due to disallowed actual MIME type (magic bytes check): {actual_mimetype_after_download} for file {original_filename}.")
            return jsonify({'success': False, 'message': 'Downloaded file has an unsupported content type after magic bytes check.'}), 400
        filename = secure_filename(original_filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        final_filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
        os.rename(temp_filepath, final_filepath)
        actual_mimetype = get_file_mimetype(final_filepath)
        if actual_mimetype not in ALLOWED_UPLOAD_MIME_TYPES:
            os.remove(final_filepath)
            _log_event(session['username'], f"Blocked URL upload due to disallowed actual MIME type: {actual_mimetype} for file {filename}.")
            return jsonify({'success': False, 'message': 'Downloaded file has an unsupported content type.'}), 400
        if not title:
            title = os.path.splitext(filename)[0]
        image_entry = {
            'id': str(uuid.uuid4()),
            'filename': unique_filename,
            'url': f'/uploads/{unique_filename}',
            'title': title,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'uploadedBy': session.get('username', 'anonymous'),
            'uploadedByDisplayId': session.get('displayId', 'anonymous'),
            'group': group_name,
            'type': 'original',
            'actual_mimetype': actual_mimetype
        }
        application_data = _load_data()
        application_data['images'].append(image_entry)
        if not any(coll['name'] == group_name for coll in application_data.get('image_collections', [])):
            application_data.setdefault('image_collections', []).append({'name': group_name})
        _save_data(application_data)
        _log_event(session.get('username', 'anonymous'), f"Uploaded image from URL: {image_url_to_check} (ID: {image_entry['id']}) to group '{group_name}'.")
        return jsonify({'success': True, 'message': 'Image uploaded successfully!', 'imageId': image_entry['id']}), 200
    except requests.exceptions.RequestException as e:
        _log_event(session['username'], f"Error fetching image from URL {image_url_to_check}: {str(e)}")
        return jsonify({'success': False, 'message': f'Failed to fetch image from URL: {str(e)}'}), 400
    except Exception as e:
        _log_event(session['username'], f"Error processing URL upload {image_url_to_check}: {str(e)}")
        return jsonify({'success': False, 'message': f'An unexpected error occurred during URL upload: {str(e)}'}), 500

