# utils.py
import os

from werkzeug.utils import secure_filename


from flask import current_app

def get_static_files():
    static_dir = os.path.join(current_app.root_path, 'static')
    cached_files = []
    for root, dirs, files in os.walk(static_dir):
        for file in files:
            full_path = os.path.join(root, file)
            relative_path = os.path.relpath(full_path, static_dir)
            cached_files.append(f"/static/{relative_path.replace(os.path.sep, '/')}")
    return cached_files


UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024 # 5MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

