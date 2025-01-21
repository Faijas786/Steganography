from django.db import models

class EncryptedImage(models.Model):
    original_image = models.ImageField(upload_to='original_images/')
    encrypted_image = models.ImageField(upload_to='encrypted_images/')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Encrypted Image {self.id} - {self.created_at}"
