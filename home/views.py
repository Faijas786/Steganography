import cv2
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.contrib import messages
import stepic
from PIL import Image
import io
from django.core.exceptions import ValidationError
import os
from django.conf import settings
from django.core.files.storage import default_storage
from cryptography.fernet import Fernet
from hashlib import sha256
import base64
from base64 import urlsafe_b64encode, b64decode
import numpy as np
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import FileSystemStorage

# Create your views here.
@login_required(login_url='/account/')
def index(request):
    return render(request, 'index.html')

def home(request):
    return render(request, 'home.html')
def edit(request):
    return render(request, 'edit.html')
def contact(request):
    return render(request, 'contact.html')
def help(request):
    return render(request, 'help.html')
def account(request):
    return render(request, 'account.html')

def save_temp_file(uploaded_file, subdirectory):
    """
    Save the uploaded file temporarily in the specified subdirectory under MEDIA_ROOT.
    """
    # Construct the full file path
    file_path = os.path.join(settings.MEDIA_ROOT, subdirectory, uploaded_file.name)
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    # Save the file in chunks to handle large files efficiently
    with default_storage.open(file_path, 'wb+') as destination:
        for chunk in uploaded_file.chunks():
            destination.write(chunk)
    
    # Return the relative path to the file
    return os.path.join(settings.MEDIA_URL, subdirectory, uploaded_file.name)

def generate_key(password):
    sha256_hash = sha256(password.encode('utf-8')).digest()
    return urlsafe_b64encode(sha256_hash)

def encrypt_text(text, password):
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted_text = fernet.encrypt(text.encode('utf-8'))
    return urlsafe_b64encode(encrypted_text).decode('utf-8')

def decrypt_text(encrypted_text, password):
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted_data = b64decode(encrypted_text)
    return fernet.decrypt(encrypted_data).decode('utf-8')
    return decrypted_text
def extract_text_from_image(image, password):
    data = stepic.decode(image)
    if data:
        try:
            return decrypt_text(data, password)
        except Exception as e:
            raise ValidationError(f"Decryption error: {str(e)}")
    raise ValidationError("No hidden text found in the image.")

def hide_text_in_image(image, text, password):
    encrypted_text = encrypt_text(text, password)
    data = encrypted_text.encode('utf-8')
    return stepic.encode(image, data)

def encryption_view(request):
    message = ''
    if request.method == 'POST':
        text = request.POST['text']
        password = request.POST['password']
        image_file = request.FILES['image']
        
        try:
            image = Image.open(image_file)

            # Convert to PNG if not already in that format
            if image.format != 'PNG':
                image = image.convert('RGBA')
                buffer = io.BytesIO()
                image.save(buffer, format="PNG")
                image = Image.open(buffer)

            # Hide text in image with password
            new_image = hide_text_in_image(image, text, password)

            # Save the new image in the project folder
            image_path = save_encrypted_image(new_image, image_file)

            message = 'Text has been encrypted in the image.'
        except Exception as e:
            message = f"Error: {str(e)}"

    return render(request, 'encryption.html', {'message': message})



def decryption_view(request):
    text = ''
    uploaded_image_url = None

    if request.method == 'POST':
        image_file = request.FILES.get('image')
        password = request.POST.get('password')

        try:
            # Validate and open the image
            validate_image(image_file)
            image = Image.open(image_file)

            # Convert to PNG if not already in that format
            if image.format != 'PNG':
                image = image.convert('RGBA')
                buffer = io.BytesIO()
                image.save(buffer, format="PNG")
                image = Image.open(buffer)

            # Extract text from the image with the password
            text = extract_text_from_image(image, password)

            # Save the uploaded image temporarily to display
            uploaded_image_url = save_temp_file(image_file, 'decrypted_images')
        except ValidationError as ve:
            text = f"Validation Error: {str(ve)}"
        except Exception as e:
            text = f"Error: {str(e)}"

    return render(request, 'decryption.html', {
        'text': text,
        'decrypted_image_url': uploaded_image_url
    })

def extract_text_from_image(image, password):
    data = stepic.decode(image)
    if data:
        # Decrypt the base64 encoded text from the image
        try:
            decrypted_text = decrypt_text(data, password)
            return decrypted_text
        except Exception as e:
            return f"Error during decryption: {str(e)}"
    return "No hidden text found."

def validate_image(image_file):
    try:
        img = Image.open(image_file)
        img.verify()  # Verify the image
    except (IOError, SyntaxError) as e:
        raise ValidationError("Invalid image file")

def save_encrypted_image(image, image_file):
    dir_path = os.path.join(settings.MEDIA_ROOT, 'encrypted_images')
    os.makedirs(dir_path, exist_ok=True)  # Create the directory if it doesn't exist
    image_path = os.path.join(dir_path, 'new_' + image_file.name)
    image.save(image_path, format="PNG")
    return image_path


# def save_image(image, subdirectory, filename):
#     dir_path = os.path.join(settings.MEDIA_ROOT, subdirectory)
#     os.makedirs(dir_path, exist_ok=True)
#     image_path = os.path.join(dir_path, filename)
#     image.save(image_path, format="PNG")
#     return image_path
def save_image(image, subdirectory, filename):
    dir_path = os.path.join(settings.MEDIA_ROOT, subdirectory)
    os.makedirs(dir_path, exist_ok=True)
    image_path = os.path.join(dir_path, filename)
    image.save(image_path, format="PNG")
    return os.path.join(settings.MEDIA_URL, subdirectory, filename) 
def edit_encryption_view(request):
    message = ''
    decrypted_text = ''
    uploaded_image_url = ''
    updated_image_url = ''

    if request.method == 'POST':
        if 'decrypt' in request.POST:  # Decrypt the current text
            current_image_file = request.FILES.get('current_image')
            current_password = request.POST.get('current_password', '').strip()

            if not current_image_file or not current_password:
                message = "Please provide the image and password to decrypt."
                return render(request, 'edit.html', {
                    'message': message,
                    'decrypted_text': decrypted_text,
                    'uploaded_image_url': uploaded_image_url
                })

            try:
                # Validate and open the uploaded image
                validate_image(current_image_file)
                image = Image.open(current_image_file)

                # Convert to PNG if not already
                if image.format != 'PNG':
                    image = image.convert('RGBA')

                # Extract the current hidden text
                decrypted_text = extract_text_from_image(image, current_password)

                # Save the uploaded image temporarily to display
                uploaded_image_url = save_temp_file(current_image_file, 'uploaded_images')
            except ValidationError as ve:
                message = f"Validation Error: {str(ve)}"
            except Exception as e:
                message = f"Error: {str(e)}"

        elif 'update' in request.POST:  # Update the encrypted image with new text
            current_image_file = request.FILES.get('current_image')
            current_password = request.POST.get('current_password', '').strip()
            new_text = request.POST.get('new_text', '').strip()
            new_password = request.POST.get('new_password', '').strip()

            if not current_image_file or not current_password or not new_text or not new_password:
                message = "All fields are required for updating."
                return render(request, 'edit.html', {
                    'message': message,
                    'decrypted_text': decrypted_text,
                    'uploaded_image_url': uploaded_image_url
                })

            try:
                # Open the uploaded image
                image = Image.open(current_image_file)
                if image.format != 'PNG':
                    image = image.convert('RGBA')

                # Extract the current hidden text to verify password
                _ = extract_text_from_image(image, current_password)

                # Hide the new text in the image
                updated_image = hide_text_in_image(image, new_text, new_password)

                # Save the updated image
                filename = f"updated_{current_image_file.name}"
                updated_image_url = save_image(updated_image, 'updated_images', filename)

                message = "Encrypted text updated successfully!"
            except ValidationError as ve:
                message = f"Validation Error: {str(ve)}"
            except Exception as e:
                message = f"Error: {str(e)}"

    return render(request, 'edit.html', {
        'message': message,
        'decrypted_text': decrypted_text,
        'uploaded_image_url': uploaded_image_url,
        'updated_image_url': updated_image_url
    })


# steganagraphy for video

def encryption_video_view(request):
    message = ""
    if request.method == "POST":
        video_file = request.FILES.get("video")
        text = request.POST.get("text")
        password = request.POST.get("password")

        if not video_file or not text or not password:
            message = "Please provide video, text, and password."
            return render(request, "encryption_video.html", {"message": message})

        # Save video temporarily
        video_path = os.path.join(settings.MEDIA_ROOT, video_file.name)
        with default_storage.open(video_path, "wb+") as destination:
            for chunk in video_file.chunks():
                destination.write(chunk)

        try:
            encrypted_text = encrypt_text(text, password)

            # Open video and prepare for writing
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                raise Exception("Could not open video file.")

            frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            fps = int(cap.get(cv2.CAP_PROP_FPS))
            codec = cv2.VideoWriter_fourcc(*'mp4v')

            output_path = os.path.join(settings.MEDIA_ROOT, "encrypted_videos", "encrypted_" + video_file.name)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            out = cv2.VideoWriter(output_path, codec, fps, (frame_width, frame_height))

            # Embed text in the first frame
            frame_idx = 0
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                if frame_idx == 0:
                    frame = embed_text_in_frame(frame, encrypted_text + b'\x00')  # Add null terminator
                out.write(frame)
                frame_idx += 1

            cap.release()
            out.release()
            message = f"Video encrypted successfully. Saved at: {output_path}"
        except Exception as e:
            message = f"Error during encryption: {e}"
        finally:
            if os.path.exists(video_path):
                os.remove(video_path)

    return render(request, "encryption_video.html", {"message": message})

# Decryption view
def decryption_video_view(request):
    decrypted_text = ""
    message = ""
    if request.method == "POST":
        video_file = request.FILES.get("video")
        password = request.POST.get("password")

        if not video_file or not password:
            message = "Please provide video and password."
            return render(request, "decryption_video.html", {"message": message})

        # Save video temporarily
        video_path = os.path.join(settings.MEDIA_ROOT, video_file.name)
        with default_storage.open(video_path, "wb+") as destination:
            for chunk in video_file.chunks():
                destination.write(chunk)

        try:
            # Open video and extract text from the first frame
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                raise Exception("Could not open video file.")

            ret, frame = cap.read()
            if not ret:
                raise Exception("Could not read the first frame.")

            encrypted_data = extract_text_from_frame(frame)
            decrypted_text = decrypt_text(encrypted_data, password)
            cap.release()
        except Exception as e:
            message = f"Error during decryption: {e}"
        finally:
            if os.path.exists(video_path):
                os.remove(video_path)

    return render(request, "decryption_video.html", {"text": decrypted_text, "message": message})


def embed_text_in_frame(frame, text):
    binary_data = ''.join(format(byte, '08b') for byte in text)
    idx = 0
    height, width, _ = frame.shape
    for row in range(height):
        for col in range(width):
            pixel = frame[row, col]
            for channel in range(3):  # RGB channels
                if idx < len(binary_data):
                    frame[row, col, channel] = (pixel[channel] & ~1) | int(binary_data[idx])
                    idx += 1
    return frame

def extract_text_from_frame(frame):
    binary_data = ""
    height, width, _ = frame.shape
    for row in range(height):
        for col in range(width):
            pixel = frame[row, col]
            for channel in pixel[:3]:  # RGB channels
                binary_data += str(channel & 1)
    all_bytes = [binary_data[i:i + 8] for i in range(0, len(binary_data), 8)]
    decoded_data = bytearray()
    for byte in all_bytes:
        decoded_data.append(int(byte, 2))
        if decoded_data[-1] == 0:  # Null terminator
            break
    return bytes(decoded_data)

def encryption_video(request):
    if request.method == "POST":
        video_file = request.FILES['video']
        text = request.POST['text']
        password = request.POST['password']

        # Save the file to the media directory after processing
        fs = FileSystemStorage()
        try:
            temp_path = os.path.join(fs.location, f"temp_{video_file.name}")
            with open(temp_path, 'wb') as temp_file:
                for chunk in video_file.chunks():
                    temp_file.write(chunk)

            # Process the file
            # Example: encrypt_text_into_video(temp_path, text, password)

            # Save the processed file permanently
            final_path = fs.save(video_file.name, open(temp_path, 'rb'))
            os.remove(temp_path)  # Clean up temporary file

        except Exception as e:
            return render(request, 'encryption.html', {'message': f"Error: {e}"})

        return render(request, 'encryption.html', {'message': "Encryption successful!"})

    return render(request, 'encryption.html')




# View for handling login and registration
def account_view(request):
    if request.method == 'POST':
        if 'login_form' in request.POST:  # Login form submitted
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('index')  # Redirect to the index page
            else:
                messages.error(request, 'Invalid username or password')

        elif 'register_form' in request.POST:  # Register form submitted
            username = request.POST['username']
            email = request.POST['email']
            password = request.POST['password']
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists')
            elif User.objects.filter(email=email).exists():
                messages.error(request, 'Email already exists')
            else:
                user = User.objects.create_user(username=username, email=email, password=password)
                user.save()
                messages.success(request, 'Registration successful! You can now log in.')
                return redirect('account')  # Redirect back to the same page

    return render(request, 'account.html')  # Render the account.html template

# View for logout
def logout_view(request):
    logout(request)
    return redirect('account')